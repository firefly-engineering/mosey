// runLaunch implements `mosey launch` — run a program under a
// mosey-reachable PTY. See the binary-level usage in main.go for
// the user-facing shape.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/cert"
	"github.com/firefly-engineering/mosey/cmd/internal/certflags"
	"github.com/firefly-engineering/mosey/transport"
	httpbackend "github.com/firefly-engineering/mosey/transport/http2"
	libp2pbackend "github.com/firefly-engineering/mosey/transport/libp2p"
	unixbackend "github.com/firefly-engineering/mosey/transport/unix"
	wsbackend "github.com/firefly-engineering/mosey/transport/websocket"
	"github.com/firefly-engineering/mosey/vterm"
)

func runLaunch(args []string, stderr *os.File) int {
	fs := flag.NewFlagSet("mosey launch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	secret := fs.String("secret", "", "owner PSK; mutually exclusive with --cert. Attachers presenting this secret get full write + resize.")
	readerSecret := fs.String("reader-secret", "", "optional reader PSK; attachers presenting it get observer (no write, no resize) access.")
	var certCfg certflags.Flags
	certCfg.Register(fs)
	mode := fs.String("mode", "supersede", "multi-client mode: supersede (newest wins) | exclusive (one at a time) | primary-observer (first writer + observers) | multi-write (everyone types)")
	httpCert := fs.String("http-cert", "", "PEM-encoded TLS cert path for https:// and wss:// listeners. Required for either scheme in --listen; h2c (http://) and ws:// listen without it.")
	httpKey := fs.String("http-key", "", "PEM-encoded TLS private key path matching --http-cert.")
	listens := stringSliceFlag{}
	fs.Var(&listens, "listen", "backend listener; repeatable. Forms: libp2p:// (default — random TCP+QUIC ports) | http://host:port (h2c) | https://host:port (TLS — requires --http-cert/--http-key) | unix:///path/to/sock (same-host) | ws://host:port (browser cleartext) | wss://host:port (browser TLS — requires --http-cert/--http-key).")
	noBootstrap := fs.Bool("no-p2p-bootstrap", false, "skip the IPFS public bootstrap set; useful for LAN-only / offline testing")
	logLevel := fs.String("log-level", "warn", "slog level: debug|info|warn|error")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "mosey launch:", err)
		return 2
	}
	if *secret == "" && !certCfg.Configured() {
		fmt.Fprintln(stderr, "mosey launch: either --secret (PSK) or --cert/--key/--master-pub (workspace cert) is required")
		return 2
	}
	if *secret != "" && certCfg.Configured() {
		fmt.Fprintln(stderr, "mosey launch: --secret and --cert are mutually exclusive (pick one auth model)")
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fmt.Fprintln(stderr, "mosey launch: missing program; usage: mosey launch --secret=SECRET -- PROGRAM [ARGS...]")
		return 2
	}
	if len(listens) == 0 {
		listens = stringSliceFlag{"libp2p://"}
	}

	logger := newLogger(stderr, *logLevel)

	authenticator, err := buildAuthenticator(*secret, *readerSecret, &certCfg, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "mosey launch:", err)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	backends, err := buildBackends(ctx, listens, *noBootstrap, *httpCert, *httpKey)
	if err != nil {
		fmt.Fprintln(stderr, "mosey launch:", err)
		return 2
	}
	defer func() {
		for _, b := range backends {
			_ = b.Close()
		}
	}()

	// Aggregate every backend behind one Transport. With a single
	// backend, Multi is a passthrough; with multiple, it routes
	// inbound handles to all of them and dispatches outbound dials
	// by URI scheme.
	multi, err := transport.Multi(backends...)
	if err != nil {
		fmt.Fprintln(stderr, "mosey launch:", err)
		return 1
	}

	authed := auth.Wrap(multi, authenticator)
	authed.Serve()

	// Wire SIGHUP → revocation-file reload when CertAuth is the
	// active authenticator and the user supplied a path. PSK auth
	// has no revocation concept — the reload goroutine just stays
	// off in that case.
	if ca, ok := authenticator.(*auth.CertAuth); ok && certCfg.RevocationPath != "" {
		go watchRevocationFile(ctx, certCfg.RevocationPath, ca, logger)
	}

	for _, ep := range authed.Endpoints() {
		fmt.Fprintf(stderr, "mosey launch: listening: %s\n", ep)
	}

	parsedMode, err := vterm.ParseMode(*mode)
	if err != nil {
		fmt.Fprintln(stderr, "mosey launch:", err)
		return 2
	}

	if err := vterm.Run(ctx, vterm.Options{Transport: authed, Logger: logger, Mode: parsedMode}, argv); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintln(stderr, "mosey launch:", err)
		return 1
	}
	return 0
}

// watchRevocationFile listens for SIGHUP and re-reads path on
// every signal, pushing the new set into ca.UpdateRevoked.
// Runs until ctx is done; the SIGHUP subscription is detached on
// exit. Errors during reload are logged at warn — the previously-
// loaded list stays in effect (best-effort policy: a malformed
// file shouldn't revoke our ability to revoke).
func watchRevocationFile(ctx context.Context, path string, ca *auth.CertAuth, logger *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	logger.Info("revocation-file SIGHUP watcher armed", "path", path)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			revoked, err := cert.LoadRevocationFile(path)
			if err != nil {
				logger.Warn("revocation reload failed (keeping previous list)", "path", path, "err", err)
				continue
			}
			ca.UpdateRevoked(revoked)
			logger.Info("revocation list reloaded", "path", path, "entries", len(revoked))
		}
	}
}

// buildAuthenticator picks between the PSK and cert authenticator
// based on which flags the user set. Flag validation already
// rejected the "both set" case before this is called.
func buildAuthenticator(secret, readerSecret string, certCfg *certflags.Flags, stderr *os.File) (auth.Authenticator, error) {
	if certCfg.Configured() {
		if readerSecret != "" {
			fmt.Fprintln(stderr, "mosey launch: --reader-secret is a PSK concept and is ignored when --cert is set (cert caps come from the cert payload)")
		}
		return certCfg.Build()
	}
	pskEntries := []auth.NamedSecret{{
		Label:  auth.LabelOwner,
		Secret: secret,
		Caps:   auth.Capabilities{Owner: true, Write: true, Resize: true},
	}}
	if readerSecret != "" {
		if readerSecret == secret {
			return nil, fmt.Errorf("--reader-secret must differ from --secret")
		}
		pskEntries = append(pskEntries, auth.NamedSecret{
			Label:  auth.LabelReader,
			Secret: readerSecret,
			Caps:   auth.Capabilities{},
		})
	}
	return auth.NewMultiPSKAuth(pskEntries)
}

// stringSliceFlag is a [flag.Value] that accumulates each repetition
// of a flag into a slice. Used for --listen.
type stringSliceFlag []string

func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

// buildBackends constructs one transport per --listen URI, picking
// the backend by URI scheme. httpCertPath / httpKeyPath are the
// TLS material used for https:// listeners; passing them with no
// matching listen URI is a config error.
func buildBackends(ctx context.Context, listens []string, noBootstrap bool, httpCertPath, httpKeyPath string) ([]transport.Transport, error) {
	out := make([]transport.Transport, 0, len(listens))
	for _, raw := range listens {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("--listen=%q: %w", raw, err)
		}
		if u.Scheme == "" {
			return nil, fmt.Errorf("--listen=%q: missing scheme", raw)
		}
		switch u.Scheme {
		case libp2pbackend.Scheme:
			opts := libp2pbackend.Options{}
			if noBootstrap {
				opts.Bootstrap = []peer.AddrInfo{}
			}
			b, err := libp2pbackend.New(ctx, opts)
			if err != nil {
				return nil, fmt.Errorf("--listen=%q: %w", raw, err)
			}
			out = append(out, b)
		case httpbackend.SchemeHTTP:
			addr := u.Host
			if addr == "" {
				addr = "0.0.0.0:0"
			}
			b, err := httpbackend.New(ctx, httpbackend.Options{ListenAddr: addr})
			if err != nil {
				return nil, fmt.Errorf("--listen=%q: %w", raw, err)
			}
			out = append(out, b)
		case httpbackend.SchemeHTTPS:
			if httpCertPath == "" || httpKeyPath == "" {
				return nil, fmt.Errorf("--listen=%q: --http-cert and --http-key are required for https:// listeners", raw)
			}
			cert, err := tls.LoadX509KeyPair(httpCertPath, httpKeyPath)
			if err != nil {
				return nil, fmt.Errorf("--listen=%q: load cert / key: %w", raw, err)
			}
			addr := u.Host
			if addr == "" {
				addr = "0.0.0.0:0"
			}
			b, err := httpbackend.New(ctx, httpbackend.Options{
				ListenAddr: addr,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
					NextProtos:   []string{"h2"},
				},
			})
			if err != nil {
				return nil, fmt.Errorf("--listen=%q: %w", raw, err)
			}
			out = append(out, b)
		case unixbackend.Scheme:
			if u.Path == "" {
				return nil, fmt.Errorf("--listen=%q: unix:// listener needs a path (e.g. unix:///tmp/mosey.sock)", raw)
			}
			b, err := unixbackend.New(ctx, unixbackend.Options{ListenAddr: u.Path})
			if err != nil {
				return nil, fmt.Errorf("--listen=%q: %w", raw, err)
			}
			out = append(out, b)
		case wsbackend.SchemeWS:
			addr := u.Host
			if addr == "" {
				addr = "0.0.0.0:0"
			}
			b, err := wsbackend.New(ctx, wsbackend.Options{ListenAddr: addr})
			if err != nil {
				return nil, fmt.Errorf("--listen=%q: %w", raw, err)
			}
			out = append(out, b)
		case wsbackend.SchemeWSS:
			if httpCertPath == "" || httpKeyPath == "" {
				return nil, fmt.Errorf("--listen=%q: --http-cert and --http-key are required for wss:// listeners", raw)
			}
			cert, err := tls.LoadX509KeyPair(httpCertPath, httpKeyPath)
			if err != nil {
				return nil, fmt.Errorf("--listen=%q: load cert / key: %w", raw, err)
			}
			addr := u.Host
			if addr == "" {
				addr = "0.0.0.0:0"
			}
			b, err := wsbackend.New(ctx, wsbackend.Options{
				ListenAddr: addr,
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				},
			})
			if err != nil {
				return nil, fmt.Errorf("--listen=%q: %w", raw, err)
			}
			out = append(out, b)
		default:
			return nil, fmt.Errorf("--listen=%q: unknown scheme %q (have: libp2p, http, https, unix, ws, wss)", raw, u.Scheme)
		}
	}
	return out, nil
}

func newLogger(out *os.File, level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	default:
		lvl = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: lvl}))
}
