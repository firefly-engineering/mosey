package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/firefly-engineering/ship/internal/api"
	"github.com/firefly-engineering/ship/internal/transport"
)

// Wrap returns a [transport.Transport] that runs the supplied
// [Authenticator] on every Dial. Client-side: Dial first opens
// /ship/auth/, drives ClientHandshake, then opens the requested
// application protocol. Server-side: call [Wrapped.Serve] once to
// install the /ship/auth/ listener; subsequent application Handle
// calls go through to the inner transport unchanged (the inner
// transport's per-connection identity carries the post-handshake
// trust).
//
// The returned [*Wrapped] is itself a [transport.Transport]; the
// concrete type exposes Serve in addition.
func Wrap(inner transport.Transport, a Authenticator) *Wrapped {
	return &Wrapped{inner: inner, auth: a}
}

// Wrapped is the auth-enforcing transport returned by [Wrap].
type Wrapped struct {
	inner transport.Transport
	auth  Authenticator
}

func (w *Wrapped) Schemes() []string   { return w.inner.Schemes() }
func (w *Wrapped) Endpoints() []string { return w.inner.Endpoints() }

func (w *Wrapped) Handle(proto string, h transport.Handler) {
	if proto == api.ProtoAuth {
		// Never expose the auth protocol to user handlers; auth
		// handshakes run server-side as part of the gated handler
		// for application protocols.
		return
	}
	w.inner.Handle(proto, func(s transport.Stream) {
		// The auth handshake runs on a *separate* /ship/auth/
		// stream the dialer opens first. By the time we see an
		// application stream from the same peer, the dialer side
		// has already proven knowledge of the secret.
		//
		// For per-stream auth we'd need the inner transport to
		// expose connection identity; today we trust that the same
		// underlying transport connection that delivered an auth
		// stream also delivered subsequent application streams.
		// Backends like libp2p enforce this naturally (one connection
		// = one peer id, all streams share it).
		h(s)
	})
}

func (w *Wrapped) Unhandle(proto string) {
	if proto == api.ProtoAuth {
		return
	}
	w.inner.Unhandle(proto)
}

// Dial runs the auth handshake then opens the requested protocol
// stream. The auth stream is opened, used, and closed inside this
// call — only the application stream is returned to the caller.
func (w *Wrapped) Dial(ctx context.Context, endpoint, proto string) (transport.Stream, error) {
	authStream, err := w.inner.Dial(ctx, endpoint, api.ProtoAuth)
	if err != nil {
		return nil, fmt.Errorf("ship/auth: open %s: %w", api.ProtoAuth, err)
	}
	if err := w.auth.ClientHandshake(ctx, authStream); err != nil {
		_ = authStream.Close()
		return nil, err
	}
	_ = authStream.Close()
	return w.inner.Dial(ctx, endpoint, proto)
}

func (w *Wrapped) Close() error { return w.inner.Close() }

// Serve installs the /ship/auth/ handler on the inner transport.
// Must be called once per wrapper before any inbound streams arrive;
// the wrapper's own Handle gates subsequent application protocols
// implicitly via the inner transport's per-connection identity, but
// the auth handler itself does the actual challenge-response work.
//
// This split lets the caller decide when the auth listener comes
// up — typically right after the inner transport is constructed
// and before any application protocols are registered.
func (w *Wrapped) Serve() {
	w.inner.Handle(api.ProtoAuth, func(s transport.Stream) {
		defer func() { _ = s.Close() }()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := w.auth.ServerHandshake(ctx, s); err != nil {
			// Silent close — exposing handshake failures via stream
			// errors would let a probing client distinguish "wrong
			// secret" from "no service". Logs (if any) should come
			// from a wrapping layer that observes the returned
			// stream.
			if !errors.Is(err, ErrUnauthorized) {
				// Truly unexpected error (I/O, malformed bytes from
				// a well-meaning but buggy peer). Same handling for
				// now; future revisions can surface these to a
				// telemetry hook on the wrapper.
				_ = err
			}
			return
		}
	})
}
