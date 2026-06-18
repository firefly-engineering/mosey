package walletsolana

// Live devnet round-trip for the write + read paths. Gated behind
// MOSEY_DEVNET_LIVE so the default `go test ./...` stays offline; run with:
//
//	set -a; source .env.local; set +a
//	MOSEY_DEVNET_LIVE=1 go test ./walletsolana/ -run TestLive -v
//
// It registers a fresh session (paid by SOLANA_KEYPAIR), mints a grant,
// then reads both back through Source against live devnet.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/wallet"
)

func loadCLIKeypair(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read keypair %s: %v", path, err)
	}
	var bytes64 []byte
	if err := json.Unmarshal(raw, &bytes64); err != nil {
		t.Fatalf("parse keypair %s: %v", path, err)
	}
	if len(bytes64) != ed25519.PrivateKeySize {
		t.Fatalf("keypair %s: got %d bytes, want %d", path, len(bytes64), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(bytes64)
}

// waitFor refreshes until cond(snapshot) is true or the deadline passes.
func waitFor(t *testing.T, s *Source, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for {
		_ = s.Refresh(context.Background())
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Second)
	}
}

func TestLiveDevnetRoundTrip(t *testing.T) {
	if os.Getenv("MOSEY_DEVNET_LIVE") != "1" {
		t.Skip("set MOSEY_DEVNET_LIVE=1 (and source .env.local) to run the live devnet check")
	}
	rpc := os.Getenv("SOLANA_RPC_URL")
	keypairPath := os.Getenv("SOLANA_KEYPAIR")
	programID := os.Getenv("MOSEY_DEVNET_PROGRAM")
	if programID == "" {
		programID = "D64mDEWvdThvEXMaxpeLRAP94wst2WcMiyzb3VqZ23T7"
	}
	if rpc == "" || keypairPath == "" {
		t.Fatal("SOLANA_RPC_URL and SOLANA_KEYPAIR must be set")
	}

	owner := loadCLIKeypair(t, keypairPath)
	ownerPub := owner.Public().(ed25519.PublicKey)

	// Fresh session + grantee each run so the test is repeatable.
	sessPub, sessPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	granteePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	src, err := New(Options{
		RPCEndpoint: rpc,
		ProgramID:   programID,
		SessionKey:  sessPub,
		Commitment:  "confirmed",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	t.Logf("owner=%s session=%s grantee=%s", wallet.Address(ownerPub), wallet.Address(sessPub), wallet.Address(granteePub))

	sig, err := src.RegisterSession(ctx, owner, sessPriv)
	if err != nil {
		t.Fatalf("RegisterSession: %v", err)
	}
	t.Logf("register_session sig=%s", sig)

	// Session must resolve, owned by our wallet, with no grants yet.
	waitFor(t, src, "session registration", func() bool {
		snap, _, serr := src.Snapshot()
		return serr == nil && snap != nil && snap.Owner().Equal(ownerPub)
	})
	snap, _, _ := src.Snapshot()
	if !snap.Owner().Equal(ownerPub) {
		t.Fatalf("owner = %s, want %s", wallet.Address(snap.Owner()), wallet.Address(ownerPub))
	}
	t.Logf("session resolved; owner=%s", wallet.Address(snap.Owner()))

	// Mint a grant: write+resize, no expiry.
	const caps = uint8(wallet.CapWrite | wallet.CapResize)
	gsig, err := src.Grant(ctx, owner, sessPub, granteePub, caps, 0)
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	t.Logf("grant sig=%s", gsig)

	waitFor(t, src, "grant", func() bool {
		s2, _, _ := src.Snapshot()
		if s2 == nil {
			return false
		}
		c, ok := s2.GrantCaps(granteePub)
		return ok && c == wallet.Caps(caps)
	})
	s2, _, _ := src.Snapshot()
	got, ok := s2.GrantCaps(granteePub)
	if !ok {
		t.Fatal("grant not found after mint")
	}
	if got != wallet.Caps(caps) {
		t.Fatalf("grant caps = %v, want %v", got, wallet.Caps(caps))
	}
	t.Logf("grant resolved; grantee=%s caps=%s", wallet.Address(granteePub), got)
}
