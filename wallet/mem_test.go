package wallet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// Compile-time checks that the in-memory types satisfy the seam.
var (
	_ Snapshot       = (*MemSnapshot)(nil)
	_ SnapshotSource = (*MemSource)(nil)
)

func mustKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub
}

func TestMemSnapshot(t *testing.T) {
	owner := mustKey(t)
	viewer := mustKey(t)
	stranger := mustKey(t)

	snap := NewMemSnapshot(owner).WithGrant(viewer, CapWrite|CapResize)

	if !owner.Equal(snap.Owner()) {
		t.Error("Owner did not round-trip")
	}
	if caps, ok := snap.GrantCaps(viewer); !ok || caps != CapWrite|CapResize {
		t.Errorf("GrantCaps(viewer) = (%v, %v), want (write|resize, true)", caps, ok)
	}
	if _, ok := snap.GrantCaps(stranger); ok {
		t.Error("GrantCaps(stranger) should report no grant")
	}
	// The owner is not a grant; ownership is resolved separately.
	if _, ok := snap.GrantCaps(owner); ok {
		t.Error("owner should not appear as a grant")
	}
}

func TestMemSource(t *testing.T) {
	owner := mustKey(t)
	viewer := mustKey(t)
	src := NewMemSource(NewMemSnapshot(owner).WithGrant(viewer, CapWrite))

	snap, fresh, err := src.Snapshot()
	if err != nil || !fresh {
		t.Fatalf("Snapshot() = (_, %v, %v), want (_, true, nil)", fresh, err)
	}
	if !owner.Equal(snap.Owner()) {
		t.Error("source snapshot lost the owner")
	}

	caps, ok, err := src.VerifyNow(context.Background(), viewer)
	if err != nil || !ok || caps != CapWrite {
		t.Errorf("VerifyNow(viewer) = (%v, %v, %v), want (write, true, nil)", caps, ok, err)
	}
}
