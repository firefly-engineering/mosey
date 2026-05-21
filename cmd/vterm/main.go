// Command vterm runs a program under a libp2p-reachable PTY.
//
// Usage:
//
//	vterm --secret=SECRET [--listen=ADDR] -- PROGRAM [ARGS...]
//
// The program runs in the foreground; vterm exits when the program
// exits. Other peers that share SECRET can attach via
// `attach --secret=SECRET ADDR` where ADDR is one of the multiaddrs
// printed at startup.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/firefly-engineering/ship/internal/auth"
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
	listen := fs.String("listen", "", "comma-separated multiaddrs to bind; default = random ports on all interfaces (TCP + QUIC)")
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

	logger := newLogger(stderr, *logLevel)

	psk, err := auth.NewPSKAuth(*secret)
	if err != nil {
		fmt.Fprintln(stderr, "vterm:", err)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	backendOpts := libp2pbackend.Options{Auth: psk}
	if *listen != "" {
		// TODO: support comma-split + multiaddr.NewMultiaddr; for v1
		// the default listen is fine. Leaving this hook in place.
		fmt.Fprintln(stderr, "vterm: --listen is not yet implemented; ignoring")
	}
	if *noBootstrap {
		backendOpts.Bootstrap = []peer.AddrInfo{} // explicit empty: skip bootstrap
	}

	backend, err := libp2pbackend.New(ctx, backendOpts)
	if err != nil {
		fmt.Fprintln(stderr, "vterm:", err)
		return 1
	}
	defer func() { _ = backend.Close() }()

	// Print the dialable endpoints so the user can paste one into
	// `attach`.
	for _, ep := range backend.Endpoints() {
		fmt.Fprintf(stderr, "vterm listening: %s\n", ep)
	}

	if err := vterm.Run(ctx, vterm.Options{Transport: backend, Logger: logger}, argv); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintln(stderr, "vterm:", err)
		return 1
	}
	return 0
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
