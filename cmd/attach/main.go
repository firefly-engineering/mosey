// Command attach connects to a libp2p-reachable vterm and bridges
// its PTY stream to the local terminal.
//
// Usage:
//
//	attach --secret=SECRET ADDR
//
// ADDR is the multiaddr printed by `vterm` at startup, e.g.
// `/ip4/192.168.1.10/tcp/4001/p2p/12D3KooW...`.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/firefly-engineering/ship/internal/attach"
	"github.com/firefly-engineering/ship/internal/auth"
	libp2pbackend "github.com/firefly-engineering/ship/internal/transport/libp2p"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr *os.File) int {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	fs.SetOutput(stderr)
	secret := fs.String("secret", "", "shared PSK; required, must match the vterm side")
	noBootstrap := fs.Bool("no-bootstrap", false, "skip the IPFS public bootstrap set; useful for LAN-only / offline testing")
	logLevel := fs.String("log-level", "warn", "slog level: debug|info|warn|error")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "attach:", err)
		return 2
	}
	if *secret == "" {
		fmt.Fprintln(stderr, "attach: --secret is required")
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "attach: expected exactly one positional argument (target multiaddr)")
		return 2
	}

	logger := newLogger(stderr, *logLevel)

	target, err := parseTarget(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "attach:", err)
		return 2
	}

	psk, err := auth.NewPSKAuth(*secret)
	if err != nil {
		fmt.Fprintln(stderr, "attach:", err)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	backendOpts := libp2pbackend.Options{Auth: psk}
	if *noBootstrap {
		backendOpts.Bootstrap = []peer.AddrInfo{}
	}

	backend, err := libp2pbackend.New(ctx, backendOpts)
	if err != nil {
		fmt.Fprintln(stderr, "attach:", err)
		return 1
	}
	defer func() { _ = backend.Close() }()

	if err := attach.Run(ctx, attach.Options{
		Host:   backend.Host(),
		Target: target,
		Logger: logger,
	}); err != nil {
		fmt.Fprintln(stderr, "attach:", err)
		return 1
	}
	return 0
}

// parseTarget converts the user's multiaddr argument into a
// [peer.AddrInfo]. The argument must include a /p2p/<peer-id>
// component — without the peer id we can't identify the dial
// target.
func parseTarget(s string) (peer.AddrInfo, error) {
	ma, err := multiaddr.NewMultiaddr(s)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("parse multiaddr: %w", err)
	}
	info, err := peer.AddrInfoFromP2pAddr(ma)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("multiaddr needs /p2p/<peer-id> suffix: %w", err)
	}
	return *info, nil
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
