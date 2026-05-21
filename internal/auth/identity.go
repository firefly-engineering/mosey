package auth

// Capabilities is the set of things a peer is authorized to do
// after a successful handshake. Today the PSK authenticator
// distinguishes "owner" (full powers) from "reader" (observer
// only); future cert-based authn will embed the bits in a signed
// claim and we'll lift them out the same way.
type Capabilities struct {
	// Owner: full control — including switching the vterm's
	// client mode and managing other clients' capabilities. Implies
	// Write + Resize.
	Owner bool

	// Write: may send input bytes to the PTY. Required to type.
	// Owner implies Write.
	Write bool

	// Resize: may emit Resize control messages. The vterm's
	// effective PTY size is min() across all currently-attached
	// clients with this cap. Owner implies Resize.
	Resize bool
}

// Identity is the auth-layer result of a successful handshake.
// Carried alongside each stream the authed transport hands off to a
// handler (via [IdentityOf]). The zero value is "unauthenticated"
// — handlers that receive a zero Identity should refuse the stream.
type Identity struct {
	// Label is a short, free-form tag used in logs and (optionally)
	// in the UI. PSK auth uses the configured name of the matching
	// secret entry ("owner", "reader"). Cert auth will surface the
	// cert subject. May be empty.
	Label string

	// Caps is the set of permissions granted to this peer.
	Caps Capabilities
}

// CanWrite reports whether the identity holds the Write
// capability, either directly or via Owner.
func (i Identity) CanWrite() bool { return i.Caps.Owner || i.Caps.Write }

// CanResize reports whether the identity holds the Resize
// capability, either directly or via Owner.
func (i Identity) CanResize() bool { return i.Caps.Owner || i.Caps.Resize }

// IsOwner reports whether the identity holds owner-level
// privileges (mode switching, capability changes).
func (i Identity) IsOwner() bool { return i.Caps.Owner }

// IsZero reports whether the identity is the zero value — i.e.
// no handshake produced it, or the handshake failed silently.
func (i Identity) IsZero() bool { return i == Identity{} }
