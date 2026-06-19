// Shared construction of the client-only multi-backend transport used
// to dial mosey hosts. Both `mosey attach` (local terminal) and
// `mosey web` (browser gateway) need the same set of dial backends —
// libp2p for peer-id / multiaddr targets, http2 + websocket for
// https:// / wss:// endpoints, and unix for same-host sockets — routed
// by URI scheme via transport.Multi.
package main

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/firefly-engineering/mosey/transport"
	httpbackend "github.com/firefly-engineering/mosey/transport/http2"
	libp2pbackend "github.com/firefly-engineering/mosey/transport/libp2p"
	unixbackend "github.com/firefly-engineering/mosey/transport/unix"
	wsbackend "github.com/firefly-engineering/mosey/transport/websocket"
)

// libp2pOptsForAttach builds the libp2p backend's options for a
// client-only process. noBootstrap skips the IPFS public set
// (LAN-only / offline use).
func libp2pOptsForAttach(noBootstrap bool) libp2pbackend.Options {
	opts := libp2pbackend.Options{}
	if noBootstrap {
		opts.Bootstrap = []peer.AddrInfo{}
	}
	return opts
}

// buildClientTransport constructs every dial backend a client process
// might need and aggregates them behind one transport.Multi. The
// returned cleanup closes all backends; call it on shutdown. None of
// the backends listen — this is a dial-only stack.
func buildClientTransport(ctx context.Context, noBootstrap, insecureTLS bool) (transport.Transport, func(), error) {
	var closers []func() error
	cleanup := func() {
		// Close in reverse construction order.
		for i := len(closers) - 1; i >= 0; i-- {
			_ = closers[i]()
		}
	}
	fail := func(err error) (transport.Transport, func(), error) {
		cleanup()
		return nil, nil, err
	}

	libp2pBackend, err := libp2pbackend.New(ctx, libp2pOptsForAttach(noBootstrap))
	if err != nil {
		return fail(fmt.Errorf("libp2p backend: %w", err))
	}
	closers = append(closers, libp2pBackend.Close)

	httpBackend, err := httpbackend.New(ctx, httpbackend.Options{InsecureSkipVerify: insecureTLS})
	if err != nil {
		return fail(fmt.Errorf("http2 backend: %w", err))
	}
	closers = append(closers, httpBackend.Close)

	unixBackend, err := unixbackend.New(ctx, unixbackend.Options{})
	if err != nil {
		return fail(fmt.Errorf("unix backend: %w", err))
	}
	closers = append(closers, unixBackend.Close)

	wsBackend, err := wsbackend.New(ctx, wsbackend.Options{InsecureSkipVerify: insecureTLS})
	if err != nil {
		return fail(fmt.Errorf("websocket backend: %w", err))
	}
	closers = append(closers, wsBackend.Close)

	multi, err := transport.Multi(libp2pBackend, httpBackend, unixBackend, wsBackend)
	if err != nil {
		return fail(fmt.Errorf("aggregate backends: %w", err))
	}
	return multi, cleanup, nil
}
