// runWeb implements `mosey web` — a self-hosted web gateway that bridges
// a browser terminal to a mosey host over libp2p. See docs/src/web-attach.md
// for the full design.
//
// The gateway is a `mosey attach` client wearing a web front-end. It
// serves an embedded xterm.js SPA and, per browser WebSocket, runs
// attach.Run against the target host, piping PTY bytes between the
// socket and the host. Front it with an HTTPS proxy (e.g. `tailscale
// serve`) — browser wallets need a secure context, and the gateway
// speaks plain HTTP so the VPN/proxy owns TLS.
//
// Two auth modes:
//   - static: one host credential (--secret / --cert / --wallet-grant)
//     for every browser, gated only by the network perimeter (Tailscale).
//   - wallet login (--wallet-login): each browser proves its wallet W and
//     signs a fresh W→K delegation in the page; the gateway mints the
//     ephemeral K and attaches with that user's on-chain access. See
//     weblogin.go.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"github.com/firefly-engineering/mosey/attach"
	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/cmd/internal/certflags"
	"github.com/firefly-engineering/mosey/cmd/internal/walletflags"
	"github.com/firefly-engineering/mosey/transport"
	"github.com/firefly-engineering/mosey/wallet"
	"github.com/firefly-engineering/mosey/webui"
)

// defaultDelegationTTL is the W→K validity window in wallet-login mode.
// Expiry gates only new handshakes, so a live attach outlives it; the
// user re-signs on reconnect. See docs/src/web-attach.md.
const defaultDelegationTTL = 16 * time.Hour

func runWeb(args []string, stderr *os.File) int {
	fs := flag.NewFlagSet("mosey web", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:8080", "HTTP listen address. Front it with an HTTPS proxy (e.g. `tailscale serve`); browser wallets require a secure context.")
	target := fs.String("target", "", "mosey host endpoint to attach to (a multiaddr, /p2p/<session-key>, or https://… URL).")
	secret := fs.String("secret", "", "static-mode PSK to authenticate to the host; mutually exclusive with --cert / --wallet-grant / --wallet-login.")
	walletLogin := fs.Bool("wallet-login", false, "per-browser wallet login: each user signs a fresh W→K delegation in the page (multi-user). Requires --session.")
	session := fs.String("session", "", "base58 session key the target host runs (required with --wallet-login; the delegation names it).")
	delegationTTL := fs.Duration("delegation-ttl", defaultDelegationTTL, "validity of each W→K delegation in --wallet-login mode")
	noBootstrap := fs.Bool("no-p2p-bootstrap", false, "skip the IPFS public bootstrap set; useful for LAN-only / offline testing")
	insecureTLS := fs.Bool("insecure-tls", false, "for https:// / wss:// targets, skip server certificate verification (self-signed dev only)")
	logLevel := fs.String("log-level", "warn", "slog level: debug|info|warn|error")
	var certCfg certflags.Flags
	certCfg.Register(fs)
	var walletCfg walletflags.ClientFlags
	walletCfg.Register(fs)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "mosey web:", err)
		return 2
	}
	if *target == "" {
		fmt.Fprintln(stderr, "mosey web: --target is required (the mosey host to bridge to)")
		return 2
	}

	staticModes := authModes(*secret != "", certCfg.Configured(), walletCfg.Configured())
	if *walletLogin {
		if staticModes != 0 {
			fmt.Fprintln(stderr, "mosey web: --wallet-login is mutually exclusive with --secret / --cert / --wallet-grant")
			return 2
		}
		if *session == "" {
			fmt.Fprintln(stderr, "mosey web: --session (base58 session key) is required with --wallet-login")
			return 2
		}
	} else {
		switch staticModes {
		case 0:
			fmt.Fprintln(stderr, "mosey web: pick an auth mode — one of --secret / --cert / --wallet-grant, or --wallet-login")
			return 2
		case 1:
			// exactly one static credential — good
		default:
			fmt.Fprintln(stderr, "mosey web: --secret, --cert, and --wallet-grant are mutually exclusive (pick one)")
			return 2
		}
	}

	logger := newLogger(stderr, *logLevel)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	multi, cleanup, err := buildClientTransport(ctx, *noBootstrap, *insecureTLS)
	if err != nil {
		fmt.Fprintln(stderr, "mosey web:", err)
		return 1
	}
	defer cleanup()

	gw := &webGateway{
		raw:           multi,
		target:        *target,
		delegationTTL: *delegationTTL,
		logger:        logger,
		logins:        map[string]*loginSession{},
	}
	if *walletLogin {
		sessionKey, err := wallet.ParseAddress(*session)
		if err != nil {
			fmt.Fprintln(stderr, "mosey web: --session:", err)
			return 2
		}
		gw.walletLogin = true
		gw.sessionKey = sessionKey
	} else {
		authenticator, err := buildAttachAuthenticator(*secret, &certCfg, &walletCfg)
		if err != nil {
			fmt.Fprintln(stderr, "mosey web:", err)
			return 2
		}
		gw.staticTransport = auth.Wrap(multi, authenticator)
	}

	srv := &http.Server{Addr: *listen, Handler: gw.mux()}
	go func() {
		<-ctx.Done()
		shutCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = srv.Shutdown(shutCtx)
	}()

	mode := "static auth"
	if gw.walletLogin {
		mode = "wallet login"
	}
	fmt.Fprintf(stderr, "mosey web: serving http://%s (%s, bridge → %s)\n", *listen, mode, *target)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "mosey web:", err)
		return 1
	}
	return 0
}

// webGateway serves the terminal UI and bridges each browser WebSocket
// to an attach session against target.
//
// In static mode, staticTransport (raw wrapped with one authenticator)
// serves every connection. In wallet-login mode, raw is left unwrapped
// and each login wraps it with its own per-user WalletAuth (see
// weblogin.go); sessionKey is the session the delegations name.
type webGateway struct {
	raw             transport.Transport
	staticTransport transport.Transport
	target          string
	logger          *slog.Logger
	upgrader        websocket.Upgrader

	walletLogin   bool
	sessionKey    ed25519.PublicKey
	delegationTTL time.Duration

	mu     sync.Mutex
	logins map[string]*loginSession
}

func (g *webGateway) mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/config", g.handleConfig)
	mux.HandleFunc("/ws", g.handleWS)
	if g.walletLogin {
		mux.HandleFunc("/login/prepare", g.handleLoginPrepare)
		mux.HandleFunc("/login/callback", g.handleLoginCallback)
	}
	mux.Handle("/", http.FileServer(http.FS(webui.FS())))
	return mux
}

// handleConfig tells the SPA which auth flow to run.
func (g *webGateway) handleConfig(w http.ResponseWriter, _ *http.Request) {
	cfg := map[string]any{"mode": "static"}
	if g.walletLogin {
		cfg = map[string]any{
			"mode":    "wallet",
			"session": wallet.Address(g.sessionKey),
		}
	}
	writeJSON(w, cfg)
}

// handleWS upgrades the request and runs one attach session for its
// lifetime. Binary frames are PTY bytes; a JSON text frame
// {type:"resize",cols,rows} drives the remote PTY size.
func (g *webGateway) handleWS(w http.ResponseWriter, r *http.Request) {
	tr := g.staticTransport
	if g.walletLogin {
		ls := g.getLogin(r.URL.Query().Get("token"))
		if ls == nil || ls.authed == nil {
			http.Error(w, "no valid login; sign in first", http.StatusUnauthorized)
			return
		}
		tr = ls.authed
	}

	conn, err := g.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote an error response.
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Browser → host: WS frames feed a pipe that backs attach's Stdin.
	stdinR, stdinW := io.Pipe()
	resizeC := make(chan [2]uint32, 8)

	go func() {
		defer cancel()
		defer func() { _ = stdinW.Close() }()
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			switch mt {
			case websocket.BinaryMessage:
				if _, err := stdinW.Write(data); err != nil {
					return
				}
			case websocket.TextMessage:
				var msg struct {
					Type string `json:"type"`
					Cols uint32 `json:"cols"`
					Rows uint32 `json:"rows"`
				}
				if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" {
					select {
					case resizeC <- [2]uint32{msg.Cols, msg.Rows}:
					default: // coalesce: drop if the forwarder is behind
					}
				}
			}
		}
	}()

	// Host → browser: attach output becomes binary WS frames.
	err = attach.Run(ctx, attach.Options{
		Transport: tr,
		Target:    g.target,
		Logger:    g.logger,
		Stdin:     stdinR,
		Stdout:    &wsWriter{conn: conn},
		ResizeC:   resizeC,
	})
	if err != nil && ctx.Err() == nil {
		g.logger.Warn("mosey web: attach session ended", "err", err)
	}
}

// wsWriter adapts a websocket connection to io.Writer, emitting each
// Write as one binary frame. gorilla connections allow a single
// concurrent writer; the mutex guards against a future control-frame
// writer racing the PTY output.
type wsWriter struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (w *wsWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
