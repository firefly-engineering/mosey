// Package auth abstracts how ship peers prove they're allowed to
// talk to each other.
//
// Today there's one [Authenticator] implementation: [PSKAuth], which
// installs libp2p's pnet (private-network) protector — peers without
// the matching pre-shared key fail the Noise handshake outright, so
// no application protocol ever surfaces to an unauthorized caller.
//
// The future direction is a cert-based [Authenticator] backed by a
// workspace master key (12-word mnemonic CA). That implementation
// will configure libp2p with a [connmgr.ConnectionGater] and consume
// a "/ship/auth/1.0.0" handshake stream to validate the cert.
// Either backend slots behind the same interface, so the higher-level
// vterm / attach code never branches on which is in use.
package auth

import (
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// Authenticator decides whether a peer is allowed to participate in
// the connection (via libp2p host options) and gets a post-Noise
// hook to perform any application-layer verification.
type Authenticator interface {
	// Name is a short identifier used in logs and error messages
	// (e.g. "psk", "cert"). Must be stable; the v1 wire format
	// doesn't carry it.
	Name() string

	// HostOptions returns the libp2p.Option slice the host must be
	// constructed with. PSK installs a pnet protector; cert-based
	// would install a connection gater.
	HostOptions() []libp2p.Option

	// VerifyPeer is called after a libp2p connection is fully
	// established (Noise complete, security upgrades done). PSK
	// returns nil — the pnet protector already gated the handshake.
	// Cert-based reads the /ship/auth stream and validates the
	// presented cert.
	//
	// Returning an error closes the connection. Implementations
	// should be fast — VerifyPeer runs in the connection-accept
	// path.
	VerifyPeer(p peer.ID, conn network.Conn) error
}
