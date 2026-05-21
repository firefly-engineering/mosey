package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	tcp "github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"golang.org/x/crypto/hkdf"
)

// pskInfo is the HKDF "info" parameter used to derive the 32-byte
// libp2p pnet key from the user-supplied secret. Stable across
// versions — changing it would break compatibility between peers
// that share the same plaintext secret but disagree about derivation.
const pskInfo = "ship.v1.pnet"

// NewPSKAuth derives a 32-byte libp2p private-network key from the
// supplied plaintext secret via HKDF-SHA256 (salt = nil, info =
// "ship.v1.pnet"). The secret can be any non-empty string; users
// typically pass it via --secret. The same secret on both peers
// produces the same pnet key, so only peers that share the secret
// can complete the Noise handshake.
//
// The secret itself is not stored on the [PSKAuth] — only its
// derived key — so a returned Authenticator can be passed through
// shared code without leaking the plaintext.
func NewPSKAuth(secret string) (*PSKAuth, error) {
	if secret == "" {
		return nil, errors.New("ship/auth: PSK secret must be non-empty")
	}
	key, err := derivePSKKey(secret)
	if err != nil {
		return nil, err
	}
	return &PSKAuth{key: key}, nil
}

// PSKAuth is an [Authenticator] backed by libp2p's pnet (private
// network) protector. Peers without the matching 32-byte key can't
// complete the Noise handshake.
type PSKAuth struct {
	key [32]byte
}

// Name implements [Authenticator].
func (a *PSKAuth) Name() string { return "psk" }

// HostOptions installs the pnet protector and pins the host to TCP
// transports only. libp2p's pnet implementation doesn't support QUIC
// — including QUIC would make host construction fail with "QUIC
// doesn't support private networks yet". PSK mode therefore loses
// UDP-based NAT traversal (DCUtR); cross-host PSK use is
// LAN-only until a cert-based authenticator (which can keep QUIC)
// lands.
func (a *PSKAuth) HostOptions() []libp2p.Option {
	// libp2p.PrivateNetwork takes a []byte view of the key.
	keyCopy := a.key
	return []libp2p.Option{
		libp2p.PrivateNetwork(keyCopy[:]),
		libp2p.NoTransports,
		libp2p.Transport(tcp.NewTCPTransport),
	}
}

// VerifyPeer is a no-op for PSK — the pnet protector already
// rejected any peer that didn't share the same key during the Noise
// handshake. Implementations of cert-based auth will do real work
// here.
func (a *PSKAuth) VerifyPeer(_ peer.ID, _ network.Conn) error { return nil }

// derivePSKKey runs HKDF-SHA256 over `secret` to produce the 32-byte
// libp2p pnet key. Returns hex-printable bytes as a sanity surface
// for tests via [PSKAuth.KeyHex].
func derivePSKKey(secret string) ([32]byte, error) {
	var out [32]byte
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte(pskInfo))
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, fmt.Errorf("ship/auth: derive PSK key: %w", err)
	}
	return out, nil
}

// KeyHex returns the derived pnet key as a hex string. Test-only —
// production code never needs to see the raw bytes.
func (a *PSKAuth) KeyHex() string { return hex.EncodeToString(a.key[:]) }
