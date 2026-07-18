package walletsolana

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/wallet"
)

func key(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func encodeSession(sessionKey, owner ed25519.PublicKey, epoch uint16) []byte {
	b := append([]byte{}, sessionDisc[:]...)
	b = append(b, sessionKey...)
	b = append(b, owner...)
	b = binary.LittleEndian.AppendUint16(b, epoch)
	return append(b, 0) // bump
}

func encodeGrant(session, grantee ed25519.PublicKey, caps wallet.Caps, expiry int64, epoch uint16) []byte {
	b := append([]byte{}, grantDisc[:]...)
	b = append(b, session...)
	b = append(b, grantee...)
	b = append(b, byte(caps))
	b = binary.LittleEndian.AppendUint64(b, uint64(expiry))
	b = binary.LittleEndian.AppendUint16(b, epoch)
	return append(b, 0)
}

func TestDecodeRoundTrip(t *testing.T) {
	sk, owner := key(t), key(t)
	s, err := decodeSession(encodeSession(sk, owner, 7))
	if err != nil {
		t.Fatalf("decodeSession: %v", err)
	}
	if !s.SessionKey.Equal(sk) || !s.Owner.Equal(owner) || s.Epoch != 7 {
		t.Errorf("session round-trip: %+v", s)
	}

	sess, grantee := key(t), key(t)
	g, err := decodeGrant(encodeGrant(sess, grantee, wallet.CapWrite|wallet.CapForge, 123, 7))
	if err != nil {
		t.Fatalf("decodeGrant: %v", err)
	}
	if !g.Session.Equal(sess) || !g.Grantee.Equal(grantee) || g.Caps != wallet.CapWrite|wallet.CapForge || g.Expiry != 123 || g.Epoch != 7 {
		t.Errorf("grant round-trip: %+v", g)
	}
}

func TestDecodeRejectsWrongDiscriminator(t *testing.T) {
	if _, err := decodeSession(encodeGrant(key(t), key(t), 0, 0, 0)); err == nil {
		t.Error("decodeSession accepted a grant account")
	}
}

func TestBuildSnapshotLiveness(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	owner, sessAddr := key(t), key(t)
	live, swept, expired, future := key(t), key(t), key(t), key(t)

	s := &Session{SessionKey: key(t), Owner: owner, Epoch: 2}
	grants := []*Grant{
		{Session: sessAddr, Grantee: live, Caps: wallet.CapWrite, Expiry: 0, Epoch: 2},
		{Session: sessAddr, Grantee: swept, Caps: wallet.CapWrite, Expiry: 0, Epoch: 1},                // old epoch
		{Session: sessAddr, Grantee: expired, Caps: wallet.CapWrite, Expiry: now.Unix() - 1, Epoch: 2}, // expired
		{Session: sessAddr, Grantee: future, Caps: wallet.CapResize, Expiry: now.Unix() + 60, Epoch: 2},
	}
	snap := buildSnapshot(s, grants, now)

	if !snap.Owner().Equal(owner) {
		t.Error("owner lost")
	}
	if c, ok := snap.GrantCaps(live); !ok || c != wallet.CapWrite {
		t.Errorf("live grant = (%v,%v)", c, ok)
	}
	if c, ok := snap.GrantCaps(future); !ok || c != wallet.CapResize {
		t.Errorf("future-expiry grant = (%v,%v)", c, ok)
	}
	if _, ok := snap.GrantCaps(swept); ok {
		t.Error("epoch-swept grant should be dead")
	}
	if _, ok := snap.GrantCaps(expired); ok {
		t.Error("expired grant should be dead")
	}
}

// fakeAccounts builds a getProgramAccounts JSON result from raw account
// blobs keyed by their (base58) pubkey.
func fakeAccounts(t *testing.T, byPubkey map[string][]byte) json.RawMessage {
	t.Helper()
	var accounts []rpcAccount
	for pk, data := range byPubkey {
		var a rpcAccount
		a.Pubkey = pk
		a.Account.Data = []string{base64.StdEncoding.EncodeToString(data), "base64"}
		accounts = append(accounts, a)
	}
	raw, err := json.Marshal(accounts)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newTestSource(t *testing.T, sessionKey ed25519.PublicKey, now func() time.Time, result json.RawMessage, callErr error) *Source {
	t.Helper()
	src, err := New(Options{
		ProgramID:    "TestProgram1111111111111111111111111111111",
		SessionKey:   sessionKey,
		MaxStaleness: 30 * time.Second,
		Now:          now,
		Call: func(_ context.Context, method string, _ []any) (json.RawMessage, error) {
			if callErr != nil {
				return nil, callErr
			}
			if method != "getProgramAccounts" {
				t.Fatalf("unexpected rpc method %q", method)
			}
			return result, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return src
}

func TestSourceRefreshSnapshot(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	clock := func() time.Time { return now }
	sessionKey, owner, viewer := key(t), key(t), key(t)
	sessAddr := key(t)
	accounts := fakeAccounts(t, map[string][]byte{
		wallet.Address(sessAddr): encodeSession(sessionKey, owner, 3),
		wallet.Address(key(t)):   encodeGrant(sessAddr, viewer, wallet.CapWrite, 0, 3),
	})

	src := newTestSource(t, sessionKey, clock, accounts, nil)
	if err := src.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	snap, fresh, err := src.Snapshot()
	if err != nil || !fresh {
		t.Fatalf("Snapshot = (_, %v, %v), want fresh", fresh, err)
	}
	if !snap.Owner().Equal(owner) {
		t.Error("wrong owner")
	}
	if c, ok := snap.GrantCaps(viewer); !ok || c != wallet.CapWrite {
		t.Errorf("viewer caps = (%v,%v), want write", c, ok)
	}
}

func TestSourceColdStartAndStaleness(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	clock := func() time.Time { return now }
	sessionKey, owner := key(t), key(t)
	sessAddr := key(t)
	accounts := fakeAccounts(t, map[string][]byte{
		wallet.Address(sessAddr): encodeSession(sessionKey, owner, 0),
	})
	src := newTestSource(t, sessionKey, clock, accounts, nil)

	// Cold start: no snapshot yet.
	if _, _, err := src.Snapshot(); err == nil {
		t.Error("Snapshot before Refresh should error (cold)")
	}
	if err := src.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, fresh, _ := src.Snapshot(); !fresh {
		t.Error("snapshot should be fresh right after refresh")
	}
	// Advance past the budget → fail-open ends, fresh becomes false.
	now = now.Add(31 * time.Second)
	if _, fresh, err := src.Snapshot(); err != nil || fresh {
		t.Errorf("Snapshot = (_, %v, %v), want stale (fresh=false, no err)", fresh, err)
	}
}

func TestSourceSessionNotRegistered(t *testing.T) {
	now := func() time.Time { return time.Unix(4_000_000, 0) }
	sessionKey := key(t)
	// Accounts contain a different session.
	accounts := fakeAccounts(t, map[string][]byte{
		wallet.Address(key(t)): encodeSession(key(t), key(t), 0),
	})
	src := newTestSource(t, sessionKey, now, accounts, nil)
	if err := src.Refresh(context.Background()); err == nil {
		t.Error("Refresh should error when our session is not registered")
	}
}

func TestSourceVerifyNow(t *testing.T) {
	now := func() time.Time { return time.Unix(5_000_000, 0) }
	sessionKey, owner, viewer := key(t), key(t), key(t)
	sessAddr := key(t)
	accounts := fakeAccounts(t, map[string][]byte{
		wallet.Address(sessAddr): encodeSession(sessionKey, owner, 1),
		wallet.Address(key(t)):   encodeGrant(sessAddr, viewer, wallet.CapResize, 0, 1),
	})
	src := newTestSource(t, sessionKey, now, accounts, nil)
	caps, ok, err := src.VerifyNow(context.Background(), viewer)
	if err != nil || !ok || caps != wallet.CapResize {
		t.Errorf("VerifyNow = (%v,%v,%v), want resize", caps, ok, err)
	}
}

// Compile-time check that Source satisfies the seam.
var _ wallet.SnapshotSource = (*Source)(nil)
