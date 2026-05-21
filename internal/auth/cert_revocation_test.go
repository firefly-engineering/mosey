package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/firefly-engineering/ship/internal/auth"
	"github.com/firefly-engineering/ship/internal/cert"
)

// TestCertAuth_UpdateRevoked_RejectsAfterMutation verifies that
// CertAuth.UpdateRevoked replaces the live revocation set —
// previously-passing handshakes are rejected once the peer's
// serial appears in the revoked map. This is the synchronous
// equivalent of "SIGHUP triggered a reload that picked up a new
// entry."
func TestCertAuth_UpdateRevoked_RejectsAfterMutation(t *testing.T) {
	t.Parallel()
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)

	clientCert, clientPriv := mintCert(t, masterPriv, "ws-1", "alice", cert.CapsBitOwner)
	serverCert, serverPriv := mintCert(t, masterPriv, "ws-1", "vterm-host", cert.CapsBitOwner)

	clientAuth, _ := auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert: clientCert, LocalPriv: clientPriv,
		MasterPub: masterPub, WorkspaceID: "ws-1",
	})
	serverAuth, _ := auth.NewCertAuth(auth.CertAuthOptions{
		LocalCert: serverCert, LocalPriv: serverPriv,
		MasterPub: masterPub, WorkspaceID: "ws-1",
	})

	// Round 1: no revocations. Handshake succeeds, alice is owner.
	{
		clientSide, serverSide := newPipeRWC()
		ch := make(chan auth.Identity, 1)
		go func() {
			id, _ := clientAuth.ClientHandshake(context.Background(), clientSide)
			ch <- id
		}()
		sid, err := serverAuth.ServerHandshake(context.Background(), serverSide)
		if err != nil {
			t.Fatalf("round 1 server: %v", err)
		}
		if !sid.IsOwner() {
			t.Errorf("round 1 expected Owner, got %+v", sid)
		}
		<-ch
	}

	// Reload revocation set — alice's serial is now revoked.
	serverAuth.UpdateRevoked(map[string]struct{}{"serial-alice": {}})

	// Round 2: server now rejects alice.
	{
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
		if !errors.Is(serverErr, auth.ErrUnauthorized) && !errors.Is(cErr, auth.ErrUnauthorized) {
			t.Errorf("post-revocation expected ErrUnauthorized; got server=%v client=%v", serverErr, cErr)
		}
	}
}
