// runWeb implements `mosey web` — a self-hosted web gateway that bridges
// a browser terminal to a mosey host over libp2p. See docs/src/web-attach.md
// for the full design.
//
// P0 shape: the gateway is a `mosey attach` client wearing a web
// front-end. It serves an embedded xterm.js SPA and, per browser
// WebSocket, runs attach.Run against a configured target host, piping
// PTY bytes between the socket and the host. Front it with an HTTPS
// proxy (e.g. `tailscale serve`) — browser wallets need a secure
// context, and the gateway itself speaks plain HTTP so the VPN/proxy
// owns TLS.
package main

import (
	"context"
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
	"github.com/firefly-engineering/mosey/webui"
)

func runWeb(args []string, stderr *os.File) int {
	fs := flag.NewFlagSet("mosey web", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", "127.0.0.1:8080", "HTTP listen address. Front it with an HTTPS proxy (e.g. `tailscale serve`); browser wallets require a secure context.")
	target := fs.String("target", "", "mosey host endpoint to attach to (required in P0; later resolved per-session from the chain).")
	secret := fs.String("secret", "", "PSK to authenticate to the host; mutually exclusive with --cert / --wallet-grant.")
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
	switch authModes(*secret != "", certCfg.Configured(), walletCfg.Configured()) {
	case 0:
		fmt.Fprintln(stderr, "mosey web: one of --secret (PSK), --cert (workspace cert), or --wallet-grant (wallet) is required")
		return 2
	case 1:
		// exactly one — good
	default:
		fmt.Fprintln(stderr, "mosey web: --secret, --cert, and --wallet-grant are mutually exclusive (pick one auth model)")
		return 2
	}

	logger := newLogger(stderr, *logLevel)

	authenticator, err := buildAttachAuthenticator(*secret, &certCfg, &walletCfg)
	if err != nil {
		fmt.Fprintln(stderr, "mosey web:", err)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	multi, cleanup, err := buildClientTransport(ctx, *noBootstrap, *insecureTLS)
	if err != nil {
		fmt.Fprintln(stderr, "mosey web:", err)
		return 1
	}
	defer cleanup()

	gw := &webGateway{
		transport: auth.Wrap(multi, authenticator),
		target:    *target,
		logger:    logger,
	}

	srv := &http.Server{Addr: *listen, Handler: gw.mux()}
	go func() {
		<-ctx.Done()
		shutCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = srv.Shutdown(shutCtx)
	}()

	fmt.Fprintf(stderr, "mosey web: serving http://%s (bridge → %s)\n", *listen, *target)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "mosey web:", err)
		return 1
	}
	return 0
}

// webGateway serves the terminal UI and bridges each browser WebSocket
// to an attach session against target.
type webGateway struct {
	transport transport.Transport
	target    string
	logger    *slog.Logger
	upgrader  websocket.Upgrader
}

func (g *webGateway) mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", g.handleWS)
	mux.Handle("/", http.FileServer(http.FS(webui.FS())))
	return mux
}

// handleWS upgrades the request and runs one attach session for its
// lifetime. Binary frames are PTY bytes; a JSON text frame
// {type:"resize",cols,rows} drives the remote PTY size.
func (g *webGateway) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := g.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade already wrote an error response.
		return
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
		Transport: g.transport,
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
