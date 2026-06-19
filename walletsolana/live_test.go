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

// waitSnap polls the cached snapshot (no manual Refresh) until cond holds,
// so it observes only background refreshes — poll or accountSubscribe push.
func waitSnap(t *testing.T, s *Source, d time.Duration, what string, cond func(wallet.Snapshot) bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		snap, _, err := s.Snapshot()
		if err == nil && snap != nil && cond(snap) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func liveEnv(t *testing.T) (rpc, keypairPath, programID string) {
	t.Helper()
	if os.Getenv("MOSEY_DEVNET_LIVE") != "1" {
		t.Skip("set MOSEY_DEVNET_LIVE=1 (and source .env.local) to run the live devnet check")
	}
	rpc = os.Getenv("SOLANA_RPC_URL")
	keypairPath = os.Getenv("SOLANA_KEYPAIR")
	programID = os.Getenv("MOSEY_DEVNET_PROGRAM")
	if programID == "" {
		programID = "D64mDEWvdThvEXMaxpeLRAP94wst2WcMiyzb3VqZ23T7"
	}
	if rpc == "" || keypairPath == "" {
		t.Fatal("SOLANA_RPC_URL and SOLANA_KEYPAIR must be set")
	}
	return rpc, keypairPath, programID
}

// TestLiveDevnetPushRefresh proves the accountSubscribe path against live
// devnet: with the backstop poll set to 2 minutes, a bump_epoch (which
// mutates the subscribed Session account) must propagate to the snapshot
// within seconds — so the update can only have come from the WS push.
func TestLiveDevnetPushRefresh(t *testing.T) {
	rpc, keypairPath, programID := liveEnv(t)
	owner := loadCLIKeypair(t, keypairPath)
	ctx := context.Background()

	sessPub, sessPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	granteePub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	src, err := New(Options{
		RPCEndpoint:  rpc,
		ProgramID:    programID,
		SessionKey:   sessPub,
		Commitment:   "confirmed",
		PollInterval: 2 * time.Minute, // long: any fast update is the push, not the poll
	})
	if err != nil {
		t.Fatal(err)
	}
	src.reconcileInterval = 2 * time.Second // subscribe promptly after the first refresh

	// Register the session and mint a grant, then start the watcher.
	if _, err := src.RegisterSession(ctx, owner, sessPriv); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := src.Grant(ctx, owner, sessPub, granteePub, uint8(wallet.CapWrite), 0); err != nil {
		t.Fatalf("grant: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go src.Run(runCtx, func(err error) { t.Logf("run: %v", err) })

	// Initial refresh + subscriptions settle; the grant becomes visible.
	waitSnap(t, src, 40*time.Second, "grant to appear", func(s wallet.Snapshot) bool {
		_, ok := s.GrantCaps(granteePub)
		return ok
	})
	time.Sleep(3 * time.Second) // ensure the Session subscription is established
	t.Logf("grant visible; bumping epoch")

	// Mutate the subscribed Session account; the grant's old epoch is swept.
	start := time.Now()
	if _, err := src.BumpEpoch(ctx, owner, sessPub); err != nil {
		t.Fatalf("bump-epoch: %v", err)
	}
	waitSnap(t, src, 30*time.Second, "epoch sweep via push", func(s wallet.Snapshot) bool {
		_, ok := s.GrantCaps(granteePub)
		return !ok
	})
	t.Logf("push-driven epoch sweep observed %s after bump (poll interval is 2m)", time.Since(start).Round(time.Millisecond))
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
