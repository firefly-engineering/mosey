// Package walletsolana implements a Solana-backed wallet.SnapshotSource
// for the mosey-session program: it reads on-chain Session + Grant
// accounts over JSON-RPC and resolves ownership/grants for one session.
//
// Reads need only getProgramAccounts (no PDA derivation), so this
// package hand-rolls the two RPC calls it uses rather than depending on
// a full Solana SDK. The account layout below must match the Anchor
// program in programs/mosey-session.
package walletsolana

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/firefly-engineering/mosey/wallet"
)

// Anchor prefixes each account's data with an 8-byte discriminator:
// sha256("account:<Name>")[:8].
func discriminator(name string) [8]byte {
	sum := sha256.Sum256([]byte("account:" + name))
	var d [8]byte
	copy(d[:], sum[:8])
	return d
}

var (
	sessionDisc = discriminator("Session")
	grantDisc   = discriminator("Grant")
)

const (
	sessionLen = 8 + 32 + 32 + 2 + 1         // disc + session_key + owner + epoch + bump
	grantLen   = 8 + 32 + 32 + 1 + 8 + 2 + 1 // disc + session + grantee + caps + expiry + epoch + bump
)

// Session mirrors the on-chain account (sans bump, unused off-chain).
type Session struct {
	SessionKey ed25519.PublicKey
	Owner      ed25519.PublicKey
	Epoch      uint16
}

// Grant mirrors the on-chain account.
type Grant struct {
	Session ed25519.PublicKey
	Grantee ed25519.PublicKey
	Caps    wallet.Caps
	Expiry  int64
	Epoch   uint16
}

var errWrongDiscriminator = errors.New("walletsolana: account discriminator mismatch")

func decodeSession(data []byte) (*Session, error) {
	if len(data) < sessionLen {
		return nil, fmt.Errorf("walletsolana: session account is %d bytes, want >= %d", len(data), sessionLen)
	}
	if [8]byte(data[:8]) != sessionDisc {
		return nil, errWrongDiscriminator
	}
	off := 8
	s := &Session{
		SessionKey: ed25519.PublicKey(append([]byte(nil), data[off:off+32]...)),
		Owner:      ed25519.PublicKey(append([]byte(nil), data[off+32:off+64]...)),
		Epoch:      binary.LittleEndian.Uint16(data[off+64 : off+66]),
	}
	return s, nil
}

func decodeGrant(data []byte) (*Grant, error) {
	if len(data) < grantLen {
		return nil, fmt.Errorf("walletsolana: grant account is %d bytes, want >= %d", len(data), grantLen)
	}
	if [8]byte(data[:8]) != grantDisc {
		return nil, errWrongDiscriminator
	}
	off := 8
	g := &Grant{
		Session: ed25519.PublicKey(append([]byte(nil), data[off:off+32]...)),
		Grantee: ed25519.PublicKey(append([]byte(nil), data[off+32:off+64]...)),
		Caps:    wallet.Caps(data[off+64]),
		Expiry:  int64(binary.LittleEndian.Uint64(data[off+65 : off+73])),
		Epoch:   binary.LittleEndian.Uint16(data[off+73 : off+75]),
	}
	return g, nil
}
