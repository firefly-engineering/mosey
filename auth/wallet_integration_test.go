package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/transport"
	"github.com/firefly-engineering/mosey/wallet"
)

// TestWalletAuth_AcrossBackends drives the wallet authenticator through
// auth.Wrap over real transports — the first end-to-end slice. It uses
// the in-memory snapshot source (no chain): an owner attaching directly,
// and a viewer with an on-chain write grant. Both prove control of an
// ephemeral connection key; the server's IdentityOf must reflect the
// folded caps.
func TestWalletAuth_AcrossBackends(t *testing.T) {
	t.Parallel()

	mkKey := func(t *testing.T) ed25519.PrivateKey {
		t.Helper()
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("genkey: %v", err)
		}
		return priv
	}
	pub := func(p ed25519.PrivateKey) ed25519.PublicKey { return p.Public().(ed25519.PublicKey) }

	session := mkKey(t)
	sessionID := pub(session)
	owner := mkKey(t)
	viewer := mkKey(t)
	ownerKc := mkKey(t)
	viewerKc := mkKey(t)

	src := wallet.NewMemSource(
		wallet.NewMemSnapshot(pub(owner)).WithGrant(pub(viewer), wallet.CapWrite),
	)

	deleg := func(signer ed25519.PrivateKey, delegate ed25519.PublicKey, caps wallet.Caps) wallet.Delegation {
		now := time.Now()
		return wallet.Sign(signer, wallet.Fields{
			SessionID: sessionID,
			Delegator: pub(signer),
			Delegate:  delegate,
			Caps:      caps,
			NotBefore: now.Add(-time.Minute),
			NotAfter:  now.Add(time.Hour),
			Nonce:     make([]byte, 16),
		})
	}

	serverAuth, err := auth.NewWalletServerAuth(auth.ServerOptions{SessionKey: session, Source: src})
	if err != nil {
		t.Fatalf("server auth: %v", err)
	}
	mkClient := func(t *testing.T, conn ed25519.PrivateKey, chain []wallet.Delegation) *auth.WalletAuth {
		t.Helper()
		c, err := auth.NewWalletClientAuth(auth.ClientOptions{ConnKey: conn, Chain: chain, ExpectSession: sessionID})
		if err != nil {
			t.Fatalf("client auth: %v", err)
		}
		return c
	}

	backends := []struct {
		name  string
		setup func(t *testing.T, ctx context.Context) (server, client transport.Transport)
	}{
		{"unix", setupUnixPair},
		{"websocket", setupWebSocketPair},
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			server, client := b.setup(t, ctx)

			authedServer := auth.Wrap(server, serverAuth)
			authedServer.Serve()

			const testProto = "/test/wallet/1"
			gotID := make(chan auth.Identity, 2)
			authedServer.Handle(testProto, func(s transport.Stream) {
				gotID <- auth.IdentityOf(s)
				var buf [1]byte
				_, _ = s.Read(buf[:])
				_ = s.Close()
			})

			endpoints := authedServer.Endpoints()
			if len(endpoints) == 0 {
				t.Fatal("server published no endpoints")
			}
			target := endpoints[0]

			ownerWrap := auth.Wrap(client, mkClient(t, ownerKc, []wallet.Delegation{
				deleg(owner, pub(ownerKc), wallet.AllCaps),
			}))
			runRole(t, ctx, ownerWrap, target, testProto, gotID, "owner", auth.Identity{
				Label: wallet.Address(pub(owner)),
				Caps:  auth.Capabilities{Owner: true, Write: true, Resize: true},
			})

			viewerWrap := auth.Wrap(client, mkClient(t, viewerKc, []wallet.Delegation{
				deleg(viewer, pub(viewerKc), wallet.CapWrite),
			}))
			runRole(t, ctx, viewerWrap, target, testProto, gotID, "viewer", auth.Identity{
				Label: wallet.Address(pub(viewer)),
				Caps:  auth.Capabilities{Write: true},
			})
		})
	}
}
