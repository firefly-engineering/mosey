package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/wallet"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestGrantBearerRoundTrip runs `mosey grant` to produce a bearer grant,
// then uses the emitted chain + connection key to attach — proving the
// off-chain "owner forges a grant" loop end to end. A write+resize grant
// must NOT confer owner/admin.
func TestGrantBearerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ownerPub, ownerPriv := genKey(t)
	sessionPub, sessionPriv := genKey(t)

	ownerKeyPath := filepath.Join(dir, "owner.key")
	if err := os.WriteFile(ownerKeyPath, []byte(hex.EncodeToString(ownerPriv)), 0o600); err != nil {
		t.Fatal(err)
	}

	null := devNull(t)
	code := runGrant([]string{
		"--wallet-keypair=" + ownerKeyPath,
		"--session=" + wallet.Address(sessionPub),
		"--caps=write, resize",
		"--out=" + dir,
	}, null, null)
	if code != 0 {
		t.Fatalf("runGrant exit %d", code)
	}

	chainBlob, err := os.ReadFile(filepath.Join(dir, "grant.json"))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := wallet.DecodeChain(chainBlob)
	if err != nil {
		t.Fatal(err)
	}
	connHex, err := os.ReadFile(filepath.Join(dir, "conn.key"))
	if err != nil {
		t.Fatal(err)
	}
	connRaw, err := hex.DecodeString(strings.TrimSpace(string(connHex)))
	if err != nil {
		t.Fatal(err)
	}
	connKey := ed25519.PrivateKey(connRaw)

	server, err := auth.NewWalletServerAuth(auth.ServerOptions{
		SessionKey: sessionPriv,
		Source:     wallet.NewMemSource(wallet.NewMemSnapshot(ownerPub)),
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := auth.NewWalletClientAuth(auth.ClientOptions{
		ConnKey: connKey, Chain: chain, ExpectSession: sessionPub,
	})
	if err != nil {
		t.Fatal(err)
	}

	srvID, srvErr, cliErr := grantHandshake(server, client)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("handshake: server=%v client=%v", srvErr, cliErr)
	}
	if !srvID.CanWrite() || !srvID.CanResize() {
		t.Errorf("caps = %+v, want write+resize", srvID.Caps)
	}
	if srvID.IsOwner() {
		t.Error("a write+resize bearer grant must not confer owner/admin")
	}
	if srvID.Label != wallet.Address(ownerPub) {
		t.Errorf("label = %q, want owner address", srvID.Label)
	}
}

func TestGrantWalletBoundOmitsConnKey(t *testing.T) {
	dir := t.TempDir()
	_, ownerPriv := genKey(t)
	sessionPub, _ := genKey(t)
	delegatePub, _ := genKey(t)

	ownerKeyPath := filepath.Join(dir, "owner.key")
	if err := os.WriteFile(ownerKeyPath, []byte(hex.EncodeToString(ownerPriv)), 0o600); err != nil {
		t.Fatal(err)
	}

	null := devNull(t)
	code := runGrant([]string{
		"--wallet-keypair=" + ownerKeyPath,
		"--session=" + wallet.Address(sessionPub),
		"--to=" + wallet.Address(delegatePub),
		"--caps=view-only",
		"--out=" + dir,
	}, null, null)
	if code != 0 {
		t.Fatalf("runGrant exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "grant.json")); err != nil {
		t.Errorf("grant.json missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "conn.key")); !os.IsNotExist(err) {
		t.Error("wallet-bound grant should not emit a bearer conn.key")
	}
}

func TestGrantRequiresKeypairAndSession(t *testing.T) {
	null := devNull(t)
	if runGrant([]string{"--session=abc"}, null, null) == 0 {
		t.Error("grant without --wallet-keypair should fail")
	}
}

func grantHandshake(server, client *auth.WalletAuth) (srvID auth.Identity, srvErr, cliErr error) {
	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		srvID, srvErr = server.ServerHandshake(context.Background(), c1)
		close(done)
	}()
	_, cliErr = client.ClientHandshake(context.Background(), c2)
	c2.Close()
	<-done
	c1.Close()
	return
}
