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
// of a freshly opened [api.ProtoAuth] stream. Implementations:
//   - [PSKAuth]: HMAC challenge-response over a shared secret
//   - (planned) workspace cert backend
type Authenticator interface {
	// Name is a short identifier used in logs / errors ("psk",
	// "cert"). Stable; not part of the wire format.
	Name() string

	// ClientHandshake drives the handshake from the dialer side.
	// Returning nil signals the application stream may proceed;
	// returning an error closes the stream and (in the wrapper)
	// propagates as a dial failure.
	ClientHandshake(ctx context.Context, stream io.ReadWriteCloser) error

	// ServerHandshake drives the handshake from the listener side.
	// Returning nil signals the inbound application stream may
	// reach the registered handler; returning an error closes the
	// stream silently.
	ServerHandshake(ctx context.Context, stream io.ReadWriteCloser) error
}

// ErrUnauthorized is the canonical failure surface for handshake
// rejection — wrong secret, malformed message, replay. Callers
// distinguish "the peer wouldn't auth" from "the network broke"
// via errors.Is(err, ErrUnauthorized).
var ErrUnauthorized = errors.New("auth: peer failed authentication handshake")
