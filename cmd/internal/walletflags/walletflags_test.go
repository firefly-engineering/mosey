package walletflags

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/wallet"
)

// TestBuildRoundTrip wires ServerFlags + ClientFlags through their Build
// paths (session-key persistence, dev-owner snapshot, grant blob, conn
// key) and runs the resulting authenticators against each other,
// asserting the owner is recognized end to end.
func TestBuildRoundTrip(t *testing.T) {
	dir := t.TempDir()

	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	connPub, connPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	connKeyPath := filepath.Join(dir, "conn.key")
	if err := os.WriteFile(connKeyPath, []byte(hex.EncodeToString(connPriv)), 0o600); err != nil {
		t.Fatal(err)
	}

	// Server: creates the session key on first Build.
	sf := ServerFlags{SessionKeyPath: filepath.Join(dir, "session.key"), DevOwner: wallet.Address(ownerPub)}
	if !sf.Configured() {
		t.Fatal("ServerFlags not Configured")
	}
	serverAuth, err := sf.Build()
	if err != nil {
		t.Fatalf("ServerFlags.Build: %v", err)
	}
	sessionID := serverAuth.SessionID()

	// A grant chain: owner delegates full caps to the connection key.
	now := time.Now()
	chain := []wallet.Delegation{wallet.Sign(ownerPriv, wallet.Fields{
		SessionID: sessionID, Delegator: ownerPub, Delegate: connPub,
		Caps: wallet.AllCaps, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		Nonce: make([]byte, 16),
	})}
	blob, err := wallet.EncodeChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	grantPath := filepath.Join(dir, "grant.json")
	if err := os.WriteFile(grantPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	cf := ClientFlags{GrantPath: grantPath, ConnKeyPath: connKeyPath, Session: wallet.Address(sessionID)}
	if !cf.Configured() {
		t.Fatal("ClientFlags not Configured")
	}
	clientAuth, err := cf.Build()
	if err != nil {
		t.Fatalf("ClientFlags.Build: %v", err)
	}

	// Persisted session key must be stable across Builds.
	if again, err := sf.Build(); err != nil || !again.SessionID().Equal(sessionID) {
		t.Fatalf("session key not stable across Build: err=%v", err)
	}

	srvID, srvErr, cliErr := runHandshake(serverAuth, clientAuth)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("handshake: server=%v client=%v", srvErr, cliErr)
	}
	if !srvID.IsOwner() || srvID.Label != wallet.Address(ownerPub) {
		t.Errorf("server identity = %+v, want owner %s", srvID, wallet.Address(ownerPub))
	}
}

func runHandshake(server, client *auth.WalletAuth) (srvID auth.Identity, srvErr, cliErr error) {
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

func TestClientFlagsRequiresGrant(t *testing.T) {
	cf := ClientFlags{ConnKeyPath: "/tmp/x"}
	if _, err := cf.Build(); err == nil {
		t.Error("ClientFlags.Build accepted no --wallet-grant")
	}
}

func TestServerFlagsRequiresDevOwner(t *testing.T) {
	sf := ServerFlags{SessionKeyPath: filepath.Join(t.TempDir(), "s.key")}
	if _, err := sf.Build(); err == nil {
		t.Error("ServerFlags.Build accepted no --wallet-dev-owner")
	}
}
