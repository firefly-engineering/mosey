package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/firefly-engineering/ship/internal/api"
	"github.com/firefly-engineering/ship/internal/transport"
)

// Wrap returns a [transport.Transport] that runs the supplied
// [Authenticator] on every connection. Client-side: Dial first
// opens /ship/auth/, drives ClientHandshake, then opens the
// requested application protocol. Server-side: call [Wrapped.Serve]
// once to install the /ship/auth/ listener; subsequent application
// Handle calls are gated on a successful prior handshake from the
// same remote peer (matched by [transport.Stream.RemoteID]).
//
// Streams returned to handlers carry the peer's [Identity] —
// retrieve it via [IdentityOf]. Streams from a peer that hasn't
// completed /ship/auth/ are silently closed.
//
// The returned [*Wrapped] is itself a [transport.Transport]; the
// concrete type exposes Serve in addition.
func Wrap(inner transport.Transport, a Authenticator) *Wrapped {
	return &Wrapped{
		inner:      inner,
		auth:       a,
		identities: map[string]Identity{},
	}
}

// Wrapped is the auth-enforcing transport returned by [Wrap].
type Wrapped struct {
	inner transport.Transport
	auth  Authenticator

	mu         sync.Mutex
	identities map[string]Identity // keyed by remote id

	localIdentityMu sync.RWMutex
	localIdentity   Identity // most recent ClientHandshake result
}

func (w *Wrapped) Schemes() []string   { return w.inner.Schemes() }
func (w *Wrapped) Endpoints() []string { return w.inner.Endpoints() }

func (w *Wrapped) Handle(proto string, h transport.Handler) {
	if proto == api.ProtoAuth {
		// Reserved — application code can't register on the auth
		// protocol. Serve() installs the only valid handler.
		return
	}
	w.inner.Handle(proto, func(s transport.Stream) {
		remote := s.RemoteID()
		w.mu.Lock()
		id, ok := w.identities[remote]
		w.mu.Unlock()
		if !ok {
			// No prior auth for this peer. Refuse silently — same
			// posture the auth handshake itself takes on failure
			// (don't help probers distinguish "wrong secret" from
			// "no such service").
			_ = s.Close()
			return
		}
		h(&identityStream{Stream: s, identity: id})
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
// The returned stream carries the local [Identity] from the
// authenticator.
func (w *Wrapped) Dial(ctx context.Context, endpoint, proto string) (transport.Stream, error) {
	authStream, err := w.inner.Dial(ctx, endpoint, api.ProtoAuth)
	if err != nil {
		return nil, fmt.Errorf("ship/auth: open %s: %w", api.ProtoAuth, err)
	}
	localID, err := w.auth.ClientHandshake(ctx, authStream)
	if err != nil {
		_ = authStream.Close()
		return nil, err
	}
	_ = authStream.Close()

	w.localIdentityMu.Lock()
	w.localIdentity = localID
	w.localIdentityMu.Unlock()

	stream, err := w.inner.Dial(ctx, endpoint, proto)
	if err != nil {
		return nil, err
	}
	return &identityStream{Stream: stream, identity: localID}, nil
}

func (w *Wrapped) Close() error { return w.inner.Close() }

// Serve installs the /ship/auth/ handler on the inner transport.
// Must be called once per wrapper before any inbound application
// streams arrive (the wrapper's gated Handle silently drops
// streams from unauthenticated peers; without Serve, every peer
// looks unauthenticated).
func (w *Wrapped) Serve() {
	w.inner.Handle(api.ProtoAuth, func(s transport.Stream) {
		defer func() { _ = s.Close() }()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		identity, err := w.auth.ServerHandshake(ctx, s)
		if err != nil {
			// Silent close — exposing handshake failures via stream
			// errors would let a probing client distinguish "wrong
			// secret" from "no service". Reserved for telemetry.
			if !errors.Is(err, ErrUnauthorized) {
				_ = err
			}
			return
		}
		w.mu.Lock()
		w.identities[s.RemoteID()] = identity
		w.mu.Unlock()
	})
}

// LocalIdentity returns the most recent successful ClientHandshake
// result on this wrapper — useful for telling the user "you're
// attached as <label>" before any application stream opens. Returns
// the zero [Identity] when no client handshake has happened yet.
func (w *Wrapped) LocalIdentity() Identity {
	w.localIdentityMu.RLock()
	defer w.localIdentityMu.RUnlock()
	return w.localIdentity
}

// identityStream wraps a [transport.Stream] with an [Identity].
// Retrieve via [IdentityOf]; consumers don't need to know about
// this type's existence.
type identityStream struct {
	transport.Stream
	identity Identity
}

// Identity exposes the identity on the underlying stream. Detected
// by [IdentityOf] via a duck-typed interface — kept lowercase so
// it stays an implementation detail of this package.
func (s *identityStream) Identity() Identity { return s.identity }

// IdentityOf returns the [Identity] attached to stream, or the
// zero Identity when the stream wasn't produced by an
// auth-wrapped transport (or no handshake completed).
func IdentityOf(stream transport.Stream) Identity {
	if c, ok := stream.(interface{ Identity() Identity }); ok {
		return c.Identity()
	}
	return Identity{}
}
