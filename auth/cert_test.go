package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/api"
	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/cert"
)

// mintCert is a test helper that mints a cert for a freshly
// generated peer keypair. Returns the cert + peer's private key
// (the caller's "agent identity").
func mintCert(t *testing.T, masterPriv ed25519.PrivateKey, workspace, label string, caps uint32) (*api.Cert, ed25519.PrivateKey) {
	t.Helper()
	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	now := time.Now()
	claim := cert.Claim{
		AgentID:     "agent-" + label,
		PeerPubKey:  peerPub,
		Label:       label,
		CapsBits:    caps,
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(time.Hour),
		Serial:      "serial-" + label,
		WorkspaceID: workspace,
	}
	c, err := cert.Sign(masterPriv, claim)
	if err != nil {
		t.Fatalf("Sign %s: %v", label, err)
	}
	return c, peerPriv
}

func TestCertAuth_Handshake_Succeeds(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("master key: %v", err)
	}

	clientCert, clientPriv := mintCert(t, masterPriv, "ws-1", "alice",
		cert.CapsBitOwner|cert.CapsBitWrite|cert.CapsBitResize)
	serverCert, serverPriv := mintCert(t, masterPriv, "ws-1", "vterm-host",
		cert.CapsBitOwner|cert.CapsBitWrite|cert.CapsBitResize)

	clientAuth, err := auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert: clientCert, LocalPriv: clientPriv,
		MasterPub: masterPub, WorkspaceID: "ws-1",
	})
	if err != nil {
		t.Fatalf("client auth: %v", err)
	}
	serverAuth, err := auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert: serverCert, LocalPriv: serverPriv,
		MasterPub: masterPub, WorkspaceID: "ws-1",
	})
	if err != nil {
		t.Fatalf("server auth: %v", err)
	}

	clientSide, serverSide := newPipeRWC()

	type result struct {
		id  auth.Identity
		err error
	}
	clientCh := make(chan result, 1)
	go func() {
		id, err := clientAuth.ClientHandshake(context.Background(), clientSide)
		clientCh <- result{id: id, err: err}
	}()

	sid, serr := serverAuth.ServerHandshake(context.Background(), serverSide)
	if serr != nil {
		t.Fatalf("ServerHandshake: %v", serr)
	}
	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("ClientHandshake: %v", cr.err)
	}

	// Server identifies the client as "alice" with Owner caps.
	if sid.Label != "alice" || !sid.IsOwner() {
		t.Errorf("server saw client = %+v, want label=alice + Owner", sid)
	}
	// Client identifies the server as "vterm-host".
	if cr.id.Label != "vterm-host" || !cr.id.IsOwner() {
		t.Errorf("client saw server = %+v, want label=vterm-host + Owner", cr.id)
	}
}

func TestCertAuth_Handshake_RejectsWrongWorkspace(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)

	clientCert, clientPriv := mintCert(t, masterPriv, "ws-A", "alice", cert.CapsBitOwner)
	// Server expects "ws-B"; client's cert is for "ws-A".
	serverCert, serverPriv := mintCert(t, masterPriv, "ws-B", "vterm-host", cert.CapsBitOwner)

	clientAuth, _ := auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert: clientCert, LocalPriv: clientPriv,
		MasterPub: masterPub, WorkspaceID: "ws-A",
	})
	serverAuth, _ := auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert: serverCert, LocalPriv: serverPriv,
		MasterPub: masterPub, WorkspaceID: "ws-B",
	})

	clientSide, serverSide := newPipeRWC()
	clientErr := make(chan error, 1)
	go func() {
		_, err := clientAuth.ClientHandshake(context.Background(), clientSide)
		_ = clientSide.Close()
		clientErr <- err
	}()
	_, serverErr := serverAuth.ServerHandshake(context.Background(), serverSide)
	_ = serverSide.Close()
	cErr := <-clientErr

	if serverErr == nil && cErr == nil {
		t.Fatal("cross-workspace certs must fail")
	}
	matched := errors.Is(serverErr, auth.ErrUnauthorized) || errors.Is(cErr, auth.ErrUnauthorized)
	if !matched {
		t.Errorf("expected ErrUnauthorized; got server=%v client=%v", serverErr, cErr)
	}
}

func TestCertAuth_Handshake_RejectsRevokedCert(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)

	clientCert, clientPriv := mintCert(t, masterPriv, "ws-1", "alice", cert.CapsBitOwner)
	serverCert, serverPriv := mintCert(t, masterPriv, "ws-1", "vterm-host", cert.CapsBitOwner)

	// Server revokes alice's serial.
	clientAuth, _ := auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert: clientCert, LocalPriv: clientPriv,
		MasterPub: masterPub, WorkspaceID: "ws-1",
	})
	serverAuth, _ := auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert: serverCert, LocalPriv: serverPriv,
		MasterPub: masterPub, WorkspaceID: "ws-1",
		Revoked: map[string]struct{}{"serial-alice": {}},
	})

	clientSide, serverSide := newPipeRWC()
	clientErr := make(chan error, 1)
	go func() {
		_, err := clientAuth.ClientHandshake(context.Background(), clientSide)
		_ = clientSide.Close()
		clientErr <- err
	}()
	_, serverErr := serverAuth.ServerHandshake(context.Background(), serverSide)
	_ = serverSide.Close()
	cErr := <-clientErr

	if serverErr == nil && cErr == nil {
		t.Fatal("revoked cert must be rejected")
	}
	if !errors.Is(serverErr, auth.ErrUnauthorized) && !errors.Is(cErr, auth.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized; got server=%v client=%v", serverErr, cErr)
	}
}

func TestCertAuth_Handshake_CapsCarryThrough(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Reader-only client: no caps bits.
	clientCert, clientPriv := mintCert(t, masterPriv, "ws-1", "bob-the-reader", 0)
	serverCert, serverPriv := mintCert(t, masterPriv, "ws-1", "vterm-host", cert.CapsBitOwner)

	clientAuth, _ := auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert: clientCert, LocalPriv: clientPriv,
		MasterPub: masterPub, WorkspaceID: "ws-1",
	})
	serverAuth, _ := auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert: serverCert, LocalPriv: serverPriv,
		MasterPub: masterPub, WorkspaceID: "ws-1",
	})

	clientSide, serverSide := newPipeRWC()
	clientCh := make(chan auth.Identity, 1)
	go func() {
		id, _ := clientAuth.ClientHandshake(context.Background(), clientSide)
		clientCh <- id
	}()
	sid, err := serverAuth.ServerHandshake(context.Background(), serverSide)
	if err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	<-clientCh

	if sid.IsOwner() || sid.CanWrite() || sid.CanResize() {
		t.Errorf("reader-only cert produced elevated caps: %+v", sid)
	}
	if sid.Label != "bob-the-reader" {
		t.Errorf("label = %q, want bob-the-reader", sid.Label)
	}
}

func TestNewCertAuth_RejectsKeyCertMismatch(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)

	clientCert, _ := mintCert(t, masterPriv, "ws-1", "alice", cert.CapsBitOwner)
	// Pair the cert with a DIFFERENT private key.
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)

	_, err := auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert: clientCert, LocalPriv: wrongPriv,
		MasterPub: masterPub, WorkspaceID: "ws-1",
	})
	if err == nil {
		t.Fatal("NewCertAuth must reject a cert+key mismatch")
	}
}
