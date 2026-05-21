package cert_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/internal/cert"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func makeValidClaim(peerPub ed25519.PublicKey) cert.Claim {
	now := time.Now()
	return cert.Claim{
		AgentID:     "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		PeerPubKey:  peerPub,
		Label:       "alice",
		CapsBits:    cert.CapsBitOwner | cert.CapsBitWrite | cert.CapsBitResize,
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(time.Hour),
		Serial:      "test-serial-001",
		WorkspaceID: "ws-1",
	}
}

func TestSign_Verify_RoundTrip(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv := newKey(t)
	peerPub, _ := newKey(t)

	want := makeValidClaim(peerPub)
	c, err := cert.Sign(masterPriv, want)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got, err := cert.Verify(c, cert.VerifyOptions{
		MasterPub:   masterPub,
		WorkspaceID: "ws-1",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.AgentID != want.AgentID || got.Label != want.Label || got.Serial != want.Serial {
		t.Errorf("claim mismatch: got %+v want %+v", got, want)
	}
	if !got.HasOwner() || !got.HasWrite() || !got.HasResize() {
		t.Errorf("caps lost: %032b", got.CapsBits)
	}
}

func TestVerify_RejectsBadSignature(t *testing.T) {
	t.Parallel()
	_, masterPriv := newKey(t)
	otherPub, _ := newKey(t) // verifier uses the wrong pubkey
	peerPub, _ := newKey(t)

	c, _ := cert.Sign(masterPriv, makeValidClaim(peerPub))
	_, err := cert.Verify(c, cert.VerifyOptions{MasterPub: otherPub, WorkspaceID: "ws-1"})
	if !errors.Is(err, cert.ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerify_RejectsTamperedContent(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv := newKey(t)
	peerPub, _ := newKey(t)

	c, _ := cert.Sign(masterPriv, makeValidClaim(peerPub))
	// Flip a byte in the signed content.
	c.Content[len(c.Content)/2] ^= 0xff
	_, err := cert.Verify(c, cert.VerifyOptions{MasterPub: masterPub, WorkspaceID: "ws-1"})
	if !errors.Is(err, cert.ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerify_RejectsExpiredCert(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv := newKey(t)
	peerPub, _ := newKey(t)

	claim := makeValidClaim(peerPub)
	claim.NotAfter = time.Now().Add(-time.Minute) // already expired
	c, _ := cert.Sign(masterPriv, claim)

	_, err := cert.Verify(c, cert.VerifyOptions{MasterPub: masterPub, WorkspaceID: "ws-1"})
	if !errors.Is(err, cert.ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestVerify_RejectsNotYetValid(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv := newKey(t)
	peerPub, _ := newKey(t)

	claim := makeValidClaim(peerPub)
	claim.NotBefore = time.Now().Add(time.Hour)
	c, _ := cert.Sign(masterPriv, claim)

	_, err := cert.Verify(c, cert.VerifyOptions{MasterPub: masterPub, WorkspaceID: "ws-1"})
	if !errors.Is(err, cert.ErrExpired) {
		t.Errorf("err = %v, want ErrExpired (also fires for not-yet-valid)", err)
	}
}

func TestVerify_RejectsWrongWorkspace(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv := newKey(t)
	peerPub, _ := newKey(t)

	c, _ := cert.Sign(masterPriv, makeValidClaim(peerPub))
	_, err := cert.Verify(c, cert.VerifyOptions{MasterPub: masterPub, WorkspaceID: "ws-different"})
	if !errors.Is(err, cert.ErrWrongWorkspace) {
		t.Errorf("err = %v, want ErrWrongWorkspace", err)
	}
}

func TestVerify_RejectsRevokedSerial(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv := newKey(t)
	peerPub, _ := newKey(t)

	c, _ := cert.Sign(masterPriv, makeValidClaim(peerPub))
	_, err := cert.Verify(c, cert.VerifyOptions{
		MasterPub:   masterPub,
		WorkspaceID: "ws-1",
		Revoked:     map[string]struct{}{"test-serial-001": {}},
	})
	if !errors.Is(err, cert.ErrRevoked) {
		t.Errorf("err = %v, want ErrRevoked", err)
	}
}

func TestVerify_ReadsCapsCorrectly(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv := newKey(t)
	peerPub, _ := newKey(t)

	claim := makeValidClaim(peerPub)
	claim.CapsBits = cert.CapsBitWrite // write-only, no owner / resize
	c, _ := cert.Sign(masterPriv, claim)

	got, err := cert.Verify(c, cert.VerifyOptions{MasterPub: masterPub, WorkspaceID: "ws-1"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.HasOwner() || got.HasResize() {
		t.Errorf("expected write-only caps, got %032b", got.CapsBits)
	}
	if !got.HasWrite() {
		t.Errorf("write bit lost")
	}
}
