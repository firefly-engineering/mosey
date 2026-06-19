// runAttach implements `mosey attach` — connect to a mosey vterm
// and bridge its PTY stream to the local terminal. See main.go for
// the binary-level usage.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/firefly-engineering/mosey/attach"
	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/cmd/internal/certflags"
	"github.com/firefly-engineering/mosey/cmd/internal/walletflags"
)

func runAttach(args []string, stderr *os.File) int {
	fs := flag.NewFlagSet("mosey attach", flag.ContinueOnError)
	fs.SetOutput(stderr)
	secret := fs.String("secret", "", "shared PSK; mutually exclusive with --cert. Must match the vterm side.")
	noBootstrap := fs.Bool("no-p2p-bootstrap", false, "skip the IPFS public bootstrap set; useful for LAN-only / offline testing")
	insecureTLS := fs.Bool("insecure-tls", false, "for https:// endpoints, skip server certificate verification (self-signed dev only)")
	logLevel := fs.String("log-level", "warn", "slog level: debug|info|warn|error")
	var certCfg certflags.Flags
	certCfg.Register(fs)
	var walletCfg walletflags.ClientFlags
	walletCfg.Register(fs)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "mosey attach:", err)
		return 2
	}
	switch authModes(*secret != "", certCfg.Configured(), walletCfg.Configured()) {
	case 0:
		fmt.Fprintln(stderr, "mosey attach: one of --secret (PSK), --cert (workspace cert), or --wallet-grant (wallet) is required")
		return 2
	case 1:
		// exactly one — good
	default:
		fmt.Fprintln(stderr, "mosey attach: --secret, --cert, and --wallet-grant are mutually exclusive (pick one auth model)")
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "mosey attach: expected exactly one positional argument (endpoint)")
		return 2
	}
	target := fs.Arg(0)

	logger := newLogger(stderr, *logLevel)

	authenticator, err := buildAttachAuthenticator(*secret, &certCfg, &walletCfg)
	if err != nil {
		fmt.Fprintln(stderr, "mosey attach:", err)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Attach is client-only — buildClientTransport aggregates every
	// dial backend (libp2p / http2 / unix / websocket) behind one
	// transport.Multi, routed by URI scheme.
	multi, cleanup, err := buildClientTransport(ctx, *noBootstrap, *insecureTLS)
	if err != nil {
		fmt.Fprintln(stderr, "mosey attach:", err)
		return 1
	}
	defer cleanup()

	// Wrap with auth — Dial drives the /mosey/auth/ handshake before
	// opening the application stream. No Serve() on this side.
	authed := auth.Wrap(multi, authenticator)

	if err := attach.Run(ctx, attach.Options{
		Transport: authed,
		Target:    target,
		Logger:    logger,
	}); err != nil {
		fmt.Fprintln(stderr, "mosey attach:", err)
		return 1
	}
	return 0
}

// buildAttachAuthenticator selects between PSK and cert auth on
// the attach side. Mirror of vterm's buildAuthenticator, minus the
// reader-secret concept (attach only carries one credential).
func buildAttachAuthenticator(secret string, certCfg *certflags.Flags, walletCfg *walletflags.ClientFlags) (auth.Authenticator, error) {
	if walletCfg.Configured() {
		return walletCfg.Build()
	}
	if certCfg.Configured() {
		return certCfg.Build()
	}
	return auth.NewPSKAuth(secret)
}
