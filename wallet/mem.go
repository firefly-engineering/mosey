package wallet

import (
	"context"
	"crypto/ed25519"
)

// MemSnapshot is an in-memory Snapshot for tests and the
// --wallet-dev-owner stub. It is immutable once built.
type MemSnapshot struct {
	owner  ed25519.PublicKey
	grants map[string]Caps // key: string(pubkey)
}

// NewMemSnapshot returns a snapshot owned by owner with no grants.
func NewMemSnapshot(owner ed25519.PublicKey) *MemSnapshot {
	return &MemSnapshot{owner: owner, grants: map[string]Caps{}}
}

// WithGrant records a live grant of caps to wallet and returns the
// snapshot, for fluent construction in tests.
func (m *MemSnapshot) WithGrant(wallet ed25519.PublicKey, caps Caps) *MemSnapshot {
	m.grants[string(wallet)] = caps
	return m
}

func (m *MemSnapshot) Owner() ed25519.PublicKey { return m.owner }

func (m *MemSnapshot) GrantCaps(wallet ed25519.PublicKey) (Caps, bool) {
	c, ok := m.grants[string(wallet)]
	return c, ok
}

// MemSource is a SnapshotSource backed by a fixed MemSnapshot. It is
// always fresh and never errors — there is no chain behind it.
type MemSource struct{ snap *MemSnapshot }

// NewMemSource wraps snap as a SnapshotSource.
func NewMemSource(snap *MemSnapshot) *MemSource { return &MemSource{snap: snap} }

func (m *MemSource) Snapshot() (Snapshot, bool, error) { return m.snap, true, nil }

func (m *MemSource) VerifyNow(_ context.Context, wallet ed25519.PublicKey) (Caps, bool, error) {
	c, ok := m.snap.GrantCaps(wallet)
	return c, ok, nil
}
