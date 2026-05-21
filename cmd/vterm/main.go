// Command vterm runs a program under a ship-reachable PTY.
//
// Usage:
//
//	vterm --secret=SECRET [--listen=URI ...] -- PROGRAM [ARGS...]
//
// --listen is repeatable; each value picks a backend by URI scheme:
//
//	libp2p://         — libp2p host (default if no --listen is given)
//
// (more backends like https:// land as separate commits.)
//
// The program runs in the foreground; vterm exits when the program
// exits. Other peers that share SECRET can attach via
// `attach --secret=SECRET ENDPOINT` where ENDPOINT is one of the
// addresses printed at startup.
package main

import (
	"context"
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

	"github.com/firefly-engineering/ship/internal/auth"
	"github.com/firefly-engineering/ship/internal/transport"
	libp2pbackend "github.com/firefly-engineering/ship/internal/transport/libp2p"
	"github.com/firefly-engineering/ship/internal/vterm"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr *os.File) int {
	fs := flag.NewFlagSet("vterm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	secret := fs.String("secret", "", "shared PSK; required, must match the attach side")
	listens := stringSliceFlag{}
	fs.Var(&listens, "listen", "backend listener; repeatable (libp2p://). Default: libp2p:// with random TCP+QUIC ports.")
	noBootstrap := fs.Bool("no-bootstrap", false, "skip the IPFS public bootstrap set; useful for LAN-only / offline testing")
	logLevel := fs.String("log-level", "warn", "slog level: debug|info|warn|error")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "vterm:", err)
		return 2
	}
	if *secret == "" {
		fmt.Fprintln(stderr, "vterm: --secret is required")
		return 2
	}
	argv := fs.Args()
	if len(argv) == 0 {
		fmt.Fprintln(stderr, "vterm: missing program; usage: vterm --secret=SECRET -- PROGRAM [ARGS...]")
		return 2
	}
	if len(listens) == 0 {
		listens = stringSliceFlag{"libp2p://"}
	}

	logger := newLogger(stderr, *logLevel)

	psk, err := auth.NewPSKAuth(*secret)
	if err != nil {
		fmt.Fprintln(stderr, "vterm:", err)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	backends, err := buildBackends(ctx, listens, *noBootstrap)
	if err != nil {
		fmt.Fprintln(stderr, "vterm:", err)
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
		fmt.Fprintln(stderr, "vterm:", err)
		return 1
	}

	authed := auth.Wrap(multi, psk)
	authed.Serve()

	for _, ep := range authed.Endpoints() {
		fmt.Fprintf(stderr, "vterm listening: %s\n", ep)
	}

	if err := vterm.Run(ctx, vterm.Options{Transport: authed, Logger: logger}, argv); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintln(stderr, "vterm:", err)
		return 1
	}
	return 0
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
// the backend by URI scheme.
func buildBackends(ctx context.Context, listens []string, noBootstrap bool) ([]transport.Transport, error) {
	out := make([]transport.Transport, 0, len(listens))
	for _, raw := range listens {
		scheme, err := schemeOf(raw)
		if err != nil {
			return nil, fmt.Errorf("--listen=%q: %w", raw, err)
		}
		switch scheme {
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
		default:
			return nil, fmt.Errorf("--listen=%q: unknown scheme %q (have: libp2p)", raw, scheme)
		}
	}
	return out, nil
}

// schemeOf pulls the URI scheme from a listen value. "libp2p://" →
// "libp2p"; "https://0.0.0.0:443/ship" → "https".
func schemeOf(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	if u.Scheme == "" {
		return "", errors.New("missing scheme")
	}
	return u.Scheme, nil
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
