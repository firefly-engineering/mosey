package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/wallet"
)

func walletKey(t *testing.T, seed byte) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func walletPub(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

var walletNow = func() time.Time { return time.Date(2026, 6, 17, 14, 0, 0, 0, time.UTC) }

// deleg signs a single delegation with priv (= delegator), valid around
// walletNow().
func deleg(priv ed25519.PrivateKey, session, delegate ed25519.PublicKey, caps wallet.Caps) wallet.Delegation {
	now := walletNow()
	return wallet.Sign(priv, wallet.Fields{
		SessionID: session,
		Delegator: walletPub(priv),
		Delegate:  delegate,
		Caps:      caps,
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
		Nonce:     bytes.Repeat([]byte{9}, 16),
	})
}

// handshake runs a server and client WalletAuth against each other over
// an in-memory pipe and returns both sides' results.
func handshake(server, client *WalletAuth) (srvID, cliID Identity, srvErr, cliErr error) {
	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		srvID, srvErr = server.ServerHandshake(context.Background(), c1)
		close(done)
	}()
	cliID, cliErr = client.ClientHandshake(context.Background(), c2)
	c2.Close() // unblock the server if the client bailed before sending its proof
	<-done
	c1.Close()
	return
}

func newServer(t *testing.T, session ed25519.PrivateKey, src wallet.SnapshotSource) *WalletAuth {
	t.Helper()
	s, err := NewWalletServerAuth(ServerOptions{SessionKey: session, Source: src, Now: walletNow})
	if err != nil {
		t.Fatalf("NewWalletServerAuth: %v", err)
	}
	return s
}

func newClient(t *testing.T, conn ed25519.PrivateKey, chain []wallet.Delegation, expect ed25519.PublicKey) *WalletAuth {
	t.Helper()
	c, err := NewWalletClientAuth(ClientOptions{ConnKey: conn, Chain: chain, ExpectSession: expect, Now: walletNow})
	if err != nil {
		t.Fatalf("NewWalletClientAuth: %v", err)
	}
	return c
}

func TestWalletHandshakeOwner(t *testing.T) {
	session := walletKey(t, 1)
	sessionID := walletPub(session)
	owner := walletKey(t, 2)
	kc := walletKey(t, 50)
	src := wallet.NewMemSource(wallet.NewMemSnapshot(walletPub(owner)))

	chain := []wallet.Delegation{deleg(owner, sessionID, walletPub(kc), wallet.AllCaps)}
	srvID, _, srvErr, cliErr := handshake(
		newServer(t, session, src),
		newClient(t, kc, chain, sessionID),
	)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("handshake errors: server=%v client=%v", srvErr, cliErr)
	}
	if !srvID.IsOwner() || !srvID.CanWrite() || !srvID.CanResize() {
		t.Errorf("owner identity = %+v, want full powers", srvID)
	}
	if srvID.Label != wallet.Address(walletPub(owner)) {
		t.Errorf("label = %q, want owner address", srvID.Label)
	}
}

func TestWalletHandshakeOnChainViewer(t *testing.T) {
	session := walletKey(t, 1)
	sessionID := walletPub(session)
	owner := walletKey(t, 2)
	viewer := walletKey(t, 3)
	kc := walletKey(t, 50)
	src := wallet.NewMemSource(wallet.NewMemSnapshot(walletPub(owner)).WithGrant(walletPub(viewer), wallet.CapWrite))

	// On-chain grant: viewer self-delegates (write) to its connection key.
	chain := []wallet.Delegation{deleg(viewer, sessionID, walletPub(kc), wallet.CapWrite)}
	srvID, _, srvErr, cliErr := handshake(
		newServer(t, session, src),
		newClient(t, kc, chain, sessionID),
	)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("handshake errors: server=%v client=%v", srvErr, cliErr)
	}
	if srvID.IsOwner() {
		t.Error("viewer should not be owner")
	}
	if !srvID.CanWrite() || srvID.CanResize() {
		t.Errorf("viewer caps = %+v, want write only", srvID.Caps)
	}
}

func TestWalletHandshakeOwnerGrantIsNotAdmin(t *testing.T) {
	// The owner signs a *write-only* bearer grant to a connection key.
	// The chain roots at the owner, but the restricted caps must not
	// confer admin (owner) powers — only the full cap set does.
	session := walletKey(t, 1)
	sessionID := walletPub(session)
	owner := walletKey(t, 2)
	kc := walletKey(t, 50)
	src := wallet.NewMemSource(wallet.NewMemSnapshot(walletPub(owner)))

	chain := []wallet.Delegation{deleg(owner, sessionID, walletPub(kc), wallet.CapWrite)}
	srvID, _, srvErr, cliErr := handshake(
		newServer(t, session, src),
		newClient(t, kc, chain, sessionID),
	)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("handshake errors: server=%v client=%v", srvErr, cliErr)
	}
	if srvID.IsOwner() {
		t.Error("a write-only owner-signed grant must not confer admin")
	}
	if !srvID.CanWrite() || srvID.CanResize() {
		t.Errorf("caps = %+v, want write only", srvID.Caps)
	}
}

func TestWalletHandshakeRejectsWrongSession(t *testing.T) {
	session := walletKey(t, 1)
	owner := walletKey(t, 2)
	kc := walletKey(t, 50)
	src := wallet.NewMemSource(wallet.NewMemSnapshot(walletPub(owner)))
	chain := []wallet.Delegation{deleg(owner, walletPub(session), walletPub(kc), wallet.AllCaps)}

	// The client expects a different session than the server proves.
	wrongSession := walletPub(walletKey(t, 77))
	_, _, _, cliErr := handshake(
		newServer(t, session, src),
		newClient(t, kc, chain, wrongSession),
	)
	if !errors.Is(cliErr, ErrUnauthorized) {
		t.Fatalf("client err = %v, want ErrUnauthorized", cliErr)
	}
}

func TestWalletHandshakeRejectsUnknownRoot(t *testing.T) {
	session := walletKey(t, 1)
	sessionID := walletPub(session)
	owner := walletKey(t, 2)
	stranger := walletKey(t, 88) // not owner, not granted
	kc := walletKey(t, 50)
	src := wallet.NewMemSource(wallet.NewMemSnapshot(walletPub(owner)))

	chain := []wallet.Delegation{deleg(stranger, sessionID, walletPub(kc), wallet.CapWrite)}
	_, _, srvErr, _ := handshake(
		newServer(t, session, src),
		newClient(t, kc, chain, sessionID),
	)
	if !errors.Is(srvErr, ErrUnauthorized) {
		t.Fatalf("server err = %v, want ErrUnauthorized", srvErr)
	}
}

// onDemandSource omits the grant from its snapshot but resolves it via
// VerifyNow, exercising the cache-miss path.
type onDemandSource struct {
	owner  ed25519.PublicKey
	wallet ed25519.PublicKey
	caps   wallet.Caps
}

func (s onDemandSource) Snapshot() (wallet.Snapshot, bool, error) {
	return wallet.NewMemSnapshot(s.owner), true, nil
}

func (s onDemandSource) VerifyNow(_ context.Context, w ed25519.PublicKey) (wallet.Caps, bool, error) {
	if s.wallet.Equal(w) {
		return s.caps, true, nil
	}
	return 0, false, nil
}

func TestWalletHandshakeOnDemandVerify(t *testing.T) {
	session := walletKey(t, 1)
	sessionID := walletPub(session)
	owner := walletKey(t, 2)
	viewer := walletKey(t, 3)
	kc := walletKey(t, 50)
	src := onDemandSource{owner: walletPub(owner), wallet: walletPub(viewer), caps: wallet.CapWrite}

	chain := []wallet.Delegation{deleg(viewer, sessionID, walletPub(kc), wallet.CapWrite)}
	srvID, _, srvErr, cliErr := handshake(
		newServer(t, session, src),
		newClient(t, kc, chain, sessionID),
	)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("handshake errors: server=%v client=%v", srvErr, cliErr)
	}
	if !srvID.CanWrite() {
		t.Errorf("on-demand-verified viewer caps = %+v, want write", srvID.Caps)
	}
}

func TestWalletHandshakeOnDemandVerifyRateLimited(t *testing.T) {
	// With a burst of 1 and a frozen clock, the first cache-miss
	// handshake gets an on-demand verify; the second is rate-limited and
	// must be rejected even though the wallet has a real grant.
	session := walletKey(t, 1)
	sessionID := walletPub(session)
	owner := walletKey(t, 2)
	viewer := walletKey(t, 3)
	src := onDemandSource{owner: walletPub(owner), wallet: walletPub(viewer), caps: wallet.CapWrite}

	server, err := NewWalletServerAuth(ServerOptions{
		SessionKey: session, Source: src, Now: walletNow,
		VerifyRatePerSec: 0.0001, VerifyBurst: 1, // ~no refill at the frozen clock
	})
	if err != nil {
		t.Fatal(err)
	}

	attach := func(seed byte) (Identity, error) {
		kc := walletKey(t, seed)
		chain := []wallet.Delegation{deleg(viewer, sessionID, walletPub(kc), wallet.CapWrite)}
		id, _, srvErr, _ := handshake(server, newClient(t, kc, chain, sessionID))
		return id, srvErr
	}

	if _, err := attach(50); err != nil {
		t.Fatalf("first on-demand verify should pass: %v", err)
	}
	if _, err := attach(51); err == nil {
		t.Error("second on-demand verify should be rate-limited and rejected")
	}
}

// staleSource is always stale, exercising fail-closed.
type staleSource struct{ owner ed25519.PublicKey }

func (s staleSource) Snapshot() (wallet.Snapshot, bool, error) {
	return wallet.NewMemSnapshot(s.owner), false, nil
}
func (s staleSource) VerifyNow(context.Context, ed25519.PublicKey) (wallet.Caps, bool, error) {
	return 0, false, nil
}

func TestWalletHandshakeFailsClosedWhenStale(t *testing.T) {
	session := walletKey(t, 1)
	sessionID := walletPub(session)
	owner := walletKey(t, 2)
	kc := walletKey(t, 50)

	chain := []wallet.Delegation{deleg(owner, sessionID, walletPub(kc), wallet.AllCaps)}
	_, _, srvErr, _ := handshake(
		newServer(t, session, staleSource{owner: walletPub(owner)}),
		newClient(t, kc, chain, sessionID),
	)
	if srvErr == nil {
		t.Fatal("server accepted a handshake against a stale snapshot")
	}
}
