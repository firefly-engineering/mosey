// runLaunch implements `mosey launch` — run a program under a
// mosey-reachable PTY. See the binary-level usage in main.go for
// the user-facing shape.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/cert"
	"github.com/firefly-engineering/mosey/cmd/internal/certflags"
	"github.com/firefly-engineering/mosey/cmd/internal/walletflags"
	"github.com/firefly-engineering/mosey/transport"
	httpbackend "github.com/firefly-engineering/mosey/transport/http2"
	libp2pbackend "github.com/firefly-engineering/mosey/transport/libp2p"
	unixbackend "github.com/firefly-engineering/mosey/transport/unix"
	wsbackend "github.com/firefly-engineering/mosey/transport/websocket"
	"github.com/firefly-engineering/mosey/vterm"
)

// detachEnvFD is the env var the parent sets on the re-exec'd child
// to (a) signal "you're the detached child, take the daemon path"
// and (b) tell the child which inherited fd is the sync pipe back
// to the parent. fd 3 is the conventional first ExtraFile slot.
const detachEnvFD = "MOSEY_DETACHED_FD"

// detachReadySentinel marks end-of-handshake on the parent/child
// sync pipe — the child writes its endpoint lines, then this line,
// then closes the pipe. The parent prints everything before the
// sentinel, drops the sentinel itself, and exits 0.
const detachReadySentinel = "__mosey_ready__"

func runLaunch(args []string, stderr *os.File) int {
	fs := flag.NewFlagSet("mosey launch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	secret := fs.String("secret", "", "owner PSK; mutually exclusive with --cert. Attachers presenting this secret get full write + resize.")
	readerSecret := fs.String("reader-secret", "", "optional reader PSK; attachers presenting it get observer (no write, no resize) access.")
	var certCfg certflags.Flags
	certCfg.Register(fs)
	var walletCfg walletflags.ServerFlags
	walletCfg.Register(fs)
	mode := fs.String("mode", "supersede", "multi-client mode: supersede (newest wins) | exclusive (one at a time) | primary-observer (first writer + observers) | multi-write (everyone types)")
	httpCert := fs.String("http-cert", "", "PEM-encoded TLS cert path for https:// and wss:// listeners. Required for either scheme in --listen; h2c (http://) and ws:// listen without it.")
	httpKey := fs.String("http-key", "", "PEM-encoded TLS private key path matching --http-cert.")
	listens := stringSliceFlag{}
	fs.Var(&listens, "listen", "backend listener; repeatable. Forms: libp2p:// (default — random TCP+QUIC ports) | http://host:port (h2c) | https://host:port (TLS — requires --http-cert/--http-key) | unix:///path/to/sock (same-host) | ws://host:port (browser cleartext) | wss://host:port (browser TLS — requires --http-cert/--http-key).")
	noBootstrap := fs.Bool("no-p2p-bootstrap", false, "skip the IPFS public bootstrap set; useful for LAN-only / offline testing")
	logLevel := fs.String("log-level", "warn", "slog level: debug|info|warn|error")
	detach := fs.Bool("detach", false, "after printing listening addresses, re-exec self in a detached child and exit 0 from the parent. Stays alive across shell exit.")
	pidFile := fs.String("pidfile", "", "write the (detached) child's PID to FILE on startup; remove on exit. Only meaningful with --detach.")
	addressFile := fs.String("address-file", "", "write the (detached) child's endpoint URIs to FILE, one per line, on startup; remove on exit. Only meaningful with --detach.")
	logFile := fs.String("log-file", "", "redirect the detached child's stdout+stderr to FILE (default /dev/null). Only meaningful with --detach.")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "mosey launch:", err)
		return 2
	}
	switch authModes(*secret != "", certCfg.Configured(), walletCfg.Configured()) {
	case 0:
		fmt.Fprintln(stderr, "mosey launch: one of --secret (PSK), --cert (workspace cert), or --wallet-session-key (wallet) is required")
		return 2
	case 1:
		// exactly one — good
	default:
		fmt.Fprintln(stderr, "mosey launch: --secret, --cert, and --wallet-session-key are mutually exclusive (pick one auth model)")
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
	if !*detach {
		if *pidFile != "" || *addressFile != "" || *logFile != "" {
			fmt.Fprintln(stderr, "mosey launch: --pidfile/--address-file/--log-file are only meaningful with --detach")
			return 2
		}
	}

	// Parent half of the detach dance: re-exec self with the sync
	// pipe wired up, forward addresses to our stderr until the child
	// signals ready, then exit. The child takes the rest of runLaunch.
	if *detach && os.Getenv(detachEnvFD) == "" {
		return runLaunchDetachParent(stderr, *logFile)
	}

	logger := newLogger(stderr, *logLevel)

	authenticator, err := buildAuthenticator(*secret, *readerSecret, &certCfg, &walletCfg, stderr)
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

	endpoints := authed.Endpoints()
	for _, ep := range endpoints {
		fmt.Fprintf(stderr, "mosey launch: listening: %s\n", ep)
	}

	// Detached child path: write the same endpoint lines (plus the
	// ready sentinel) to the inherited pipe, then close it. The
	// parent is io.Copy-ing the pipe to its own stderr until it sees
	// the sentinel; closing the pipe makes that copy return cleanly.
	// We also persist pidfile/address-file at this point so a kill
	// after the parent has exited still has somewhere to look up the
	// pid + endpoints.
	if envFD := os.Getenv(detachEnvFD); envFD != "" {
		fd, parseErr := strconv.Atoi(envFD)
		if parseErr != nil {
			fmt.Fprintln(stderr, "mosey launch: bad", detachEnvFD, "value:", envFD)
			return 1
		}
		readyPipe := os.NewFile(uintptr(fd), "detach-ready")
		for _, ep := range endpoints {
			fmt.Fprintf(readyPipe, "mosey launch: listening: %s\n", ep)
		}
		fmt.Fprintln(readyPipe, detachReadySentinel)
		_ = readyPipe.Close()
		os.Unsetenv(detachEnvFD)

		if *pidFile != "" {
			if err := os.WriteFile(*pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
				fmt.Fprintln(stderr, "mosey launch: write pidfile:", err)
				return 1
			}
			defer func() { _ = os.Remove(*pidFile) }()
		}
		if *addressFile != "" {
			var b strings.Builder
			for _, ep := range endpoints {
				b.WriteString(ep)
				b.WriteByte('\n')
			}
			if err := os.WriteFile(*addressFile, []byte(b.String()), 0o644); err != nil {
				fmt.Fprintln(stderr, "mosey launch: write address-file:", err)
				return 1
			}
			defer func() { _ = os.Remove(*addressFile) }()
		}
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

// runLaunchDetachParent is the parent half of --detach: re-exec the
// same binary with its existing argv, hand the child one end of a
// pipe as fd 3, mirror the child's address lines to our own stderr
// until the child writes the ready sentinel, then exit 0. The child
// continues running with its stdio pointed at logFile (or
// /dev/null), Setsid set so SIGHUP from the parent shell can't reach
// it.
func runLaunchDetachParent(stderr *os.File, logFile string) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "mosey launch: resolve self:", err)
		return 1
	}

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		fmt.Fprintln(stderr, "mosey launch: pipe:", err)
		return 1
	}
	defer func() { _ = pipeR.Close() }()

	var childOut *os.File
	if logFile == "" {
		childOut, err = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	} else {
		childOut, err = os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	}
	if err != nil {
		fmt.Fprintln(stderr, "mosey launch: open child log:", err)
		_ = pipeW.Close()
		return 1
	}
	defer func() { _ = childOut.Close() }()

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), detachEnvFD+"=3")
	cmd.Stdin = nil
	cmd.Stdout = childOut
	cmd.Stderr = childOut
	cmd.ExtraFiles = []*os.File{pipeW}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = pipeW.Close()
		fmt.Fprintln(stderr, "mosey launch: spawn child:", err)
		return 1
	}
	// Release the parent's copy of the write end so the read side
	// EOFs cleanly when the child closes its own copy.
	_ = pipeW.Close()
	// Disown the child PID; we don't want Wait()ing on it.
	_ = cmd.Process.Release()

	scanner := bufio.NewScanner(pipeR)
	sawReady := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == detachReadySentinel {
			sawReady = true
			break
		}
		fmt.Fprintln(stderr, line)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(stderr, "mosey launch: read child sync pipe:", err)
		return 1
	}
	if !sawReady {
		fmt.Fprintln(stderr, "mosey launch: child exited before signalling ready (check --log-file for cause)")
		return 1
	}
	// Drain any trailing output the child wrote between the sentinel
	// and closing the pipe — keeps the parent's stderr in sync with
	// what the child intended to surface.
	_, _ = io.Copy(stderr, pipeR)
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
// authModes counts how many auth models are configured. Exactly one
// must be selected.
func authModes(flags ...bool) int {
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n
}

func buildAuthenticator(secret, readerSecret string, certCfg *certflags.Flags, walletCfg *walletflags.ServerFlags, stderr *os.File) (auth.Authenticator, error) {
	if walletCfg.Configured() {
		if readerSecret != "" {
			fmt.Fprintln(stderr, "mosey launch: --reader-secret is a PSK concept and is ignored with wallet auth (caps come from on-chain ownership / delegations)")
		}
		return walletCfg.Build()
	}
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
