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

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/firefly-engineering/mosey/cmd/internal/certflags"
	"github.com/firefly-engineering/mosey/attach"
	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/transport"
	httpbackend "github.com/firefly-engineering/mosey/transport/http2"
	libp2pbackend "github.com/firefly-engineering/mosey/transport/libp2p"
	unixbackend "github.com/firefly-engineering/mosey/transport/unix"
	wsbackend "github.com/firefly-engineering/mosey/transport/websocket"
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

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "mosey attach:", err)
		return 2
	}
	if *secret == "" && !certCfg.Configured() {
		fmt.Fprintln(stderr, "mosey attach: either --secret (PSK) or --cert/--key/--master-pub (workspace cert) is required")
		return 2
	}
	if *secret != "" && certCfg.Configured() {
		fmt.Fprintln(stderr, "mosey attach: --secret and --cert are mutually exclusive (pick one auth model)")
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "mosey attach: expected exactly one positional argument (endpoint)")
		return 2
	}
	target := fs.Arg(0)

	logger := newLogger(stderr, *logLevel)

	authenticator, err := buildAttachAuthenticator(*secret, &certCfg)
	if err != nil {
		fmt.Fprintln(stderr, "mosey attach:", err)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Attach is client-only — build one backend per scheme it may
	// need to dial. Multi routes Dial by URI scheme so a single
	// CLI invocation can target either backend.
	libp2pBackend, err := libp2pbackend.New(ctx, libp2pOptsForAttach(*noBootstrap))
	if err != nil {
		fmt.Fprintln(stderr, "mosey attach:", err)
		return 1
	}
	defer func() { _ = libp2pBackend.Close() }()

	httpBackend, err := httpbackend.New(ctx, httpbackend.Options{
		InsecureSkipVerify: *insecureTLS,
	}) // client-only
	if err != nil {
		fmt.Fprintln(stderr, "mosey attach:", err)
		return 1
	}
	defer func() { _ = httpBackend.Close() }()

	unixBackend, err := unixbackend.New(ctx, unixbackend.Options{}) // client-only
	if err != nil {
		fmt.Fprintln(stderr, "mosey attach:", err)
		return 1
	}
	defer func() { _ = unixBackend.Close() }()

	wsBackend, err := wsbackend.New(ctx, wsbackend.Options{
		InsecureSkipVerify: *insecureTLS,
	}) // client-only
	if err != nil {
		fmt.Fprintln(stderr, "mosey attach:", err)
		return 1
	}
	defer func() { _ = wsBackend.Close() }()

	multi, err := transport.Multi(libp2pBackend, httpBackend, unixBackend, wsBackend)
	if err != nil {
		fmt.Fprintln(stderr, "mosey attach:", err)
		return 1
	}

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
func buildAttachAuthenticator(secret string, certCfg *certflags.Flags) (auth.Authenticator, error) {
	if certCfg.Configured() {
		return certCfg.Build()
	}
	return auth.NewPSKAuth(secret)
}

// libp2pOptsForAttach builds the libp2p backend's options for a
// client-only attach process. --no-p2p-bootstrap skips the IPFS public
// set (LAN-only / offline use).
func libp2pOptsForAttach(noBootstrap bool) libp2pbackend.Options {
	opts := libp2pbackend.Options{}
	if noBootstrap {
		opts.Bootstrap = []peer.AddrInfo{}
	}
	return opts
}
