// Package auth runs ship's application-layer authentication
// handshake on top of any [transport.Transport].
//
// The transport itself provides confidentiality + integrity (libp2p
// Noise, TLS, etc.). This package adds *identity* — proves both
// peers hold the same workspace secret (PSK today; cert-based
// authenticator with workspace master key later). The handshake
// runs on a fresh [api.ProtoAuth] stream per application stream;
// failure closes the stream before any user handler sees it.
//
// [Wrap] turns any Transport into one that enforces the handshake
// transparently — vterm and attach call `auth.Wrap(libp2pBackend, psk)`
// and never deal with the auth wire format directly.
package auth

import (
	"context"
	"errors"
	"io"
)

// Authenticator runs ship's authentication handshake from each side
// of a freshly opened [api.ProtoAuth] stream. Successful handshakes
// produce an [Identity] — backends that don't distinguish identities
// (e.g. a single-secret PSK) return an Identity with full Owner
// caps so the existing "secret == permission" mental model carries
// over unchanged.
//
// Implementations:
//   - [PSKAuth]: HMAC challenge-response over one or more named
//     shared secrets (owner / reader / future roles)
//   - (planned) workspace cert backend with caps embedded in the
//     signed claim
type Authenticator interface {
	// Name is a short identifier used in logs / errors ("psk",
	// "cert"). Stable; not part of the wire format.
	Name() string

	// ClientHandshake drives the handshake from the dialer side.
	// Returns the local Identity (with caps reflecting which
	// secret / cert the client presented) on success. Error closes
	// the stream and propagates as a dial failure.
	ClientHandshake(ctx context.Context, stream io.ReadWriteCloser) (Identity, error)

	// ServerHandshake drives the handshake from the listener side.
	// Returns the remote peer's Identity on success — the auth
	// wrapper records it so subsequent application streams from
	// the same peer carry the same caps. Error closes the stream
	// silently.
	ServerHandshake(ctx context.Context, stream io.ReadWriteCloser) (Identity, error)
}

// ErrUnauthorized is the canonical failure surface for handshake
// rejection — wrong secret, malformed message, replay. Callers
// distinguish "the peer wouldn't auth" from "the network broke"
// via errors.Is(err, ErrUnauthorized).
var ErrUnauthorized = errors.New("auth: peer failed authentication handshake")
