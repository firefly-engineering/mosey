package auth_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/transport"
	h2backend "github.com/firefly-engineering/mosey/transport/http2"
	libp2pbackend "github.com/firefly-engineering/mosey/transport/libp2p"
	unixbackend "github.com/firefly-engineering/mosey/transport/unix"
	wsbackend "github.com/firefly-engineering/mosey/transport/websocket"
)

// TestIdentityOf_AcrossBackends asserts that auth.IdentityOf
// returns the post-handshake Identity uniformly regardless of which
// transport carried the bytes. The auth wrap is by design backend-
// agnostic; this test pins that contract so a future backend can't
// drift from it silently.
//
// For each backend the test runs both an owner-PSK client and a
// reader-PSK client through the same server, and verifies the
// captured Identity matches the role each client presented.
func TestIdentityOf_AcrossBackends(t *testing.T) {
	t.Parallel()

	const (
		secretOwner  = "owner-secret"
		secretReader = "reader-secret"
	)

	serverAuth, err := auth.NewMultiPSKAuth([]auth.NamedSecret{
		{Label: auth.LabelOwner, Secret: secretOwner, Caps: auth.Capabilities{Owner: true, Write: true, Resize: true}},
		{Label: auth.LabelReader, Secret: secretReader, Caps: auth.Capabilities{}},
	})
	if err != nil {
		t.Fatalf("server auth: %v", err)
	}
	ownerAuth, err := auth.NewPSKAuth(secretOwner)
	if err != nil {
		t.Fatalf("owner auth: %v", err)
	}
	readerAuth, err := auth.NewMultiPSKAuth([]auth.NamedSecret{
		{Label: auth.LabelReader, Secret: secretReader, Caps: auth.Capabilities{}},
	})
	if err != nil {
		t.Fatalf("reader auth: %v", err)
	}

	backends := []struct {
		name  string
		setup func(t *testing.T, ctx context.Context) (server, client transport.Transport)
	}{
		{"libp2p", setupLibp2pPair},
		{"http2", setupHTTP2Pair},
		{"websocket", setupWebSocketPair},
		{"unix", setupUnixPair},
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			server, client := b.setup(t, ctx)

			vtermAuthed := auth.Wrap(server, serverAuth)
			vtermAuthed.Serve()

			const testProto = "/test/identity/1"
			gotID := make(chan auth.Identity, 2)
			vtermAuthed.Handle(testProto, func(s transport.Stream) {
				gotID <- auth.IdentityOf(s)
				// Keep the stream open until the dialer closes.
				// Returning immediately would close the stream
				// underneath the dialer's pending Write below,
				// surfacing a spurious error in the test.
				var buf [1]byte
				_, _ = s.Read(buf[:])
				_ = s.Close()
			})

			endpoints := vtermAuthed.Endpoints()
			if len(endpoints) == 0 {
				t.Fatal("server published no endpoints")
			}
			target := endpoints[0]

			ownerWrap := auth.Wrap(client, ownerAuth)
			runRole(t, ctx, ownerWrap, target, testProto, gotID, "owner", auth.Identity{
				Label: auth.LabelOwner,
				Caps:  auth.Capabilities{Owner: true, Write: true, Resize: true},
			})

			// Fresh client wrap so the cached per-remote auth state
			// doesn't skip the second handshake.
			readerWrap := auth.Wrap(client, readerAuth)
			runRole(t, ctx, readerWrap, target, testProto, gotID, "reader", auth.Identity{
				Label: auth.LabelReader,
				Caps:  auth.Capabilities{},
			})
		})
	}
}

func assertIdentity(t *testing.T, role string, ch <-chan auth.Identity, want auth.Identity) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("%s: IdentityOf = %+v, want %+v", role, got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: handler never fired", role)
	}
}

// runRole dials testProto via wrap, writes a single byte to force
// stream-muxer backends (libp2p/yamux) to actually push the
// stream-open frame on the wire — without it the server-side
// handler doesn't fire until close — then asserts the captured
// identity matches want.
func runRole(t *testing.T, ctx context.Context, wrap *auth.Wrapped, target, testProto string, gotID <-chan auth.Identity, role string, want auth.Identity) {
	t.Helper()
	s, err := wrap.Dial(ctx, target, testProto)
	if err != nil {
		t.Fatalf("%s dial: %v", role, err)
	}
	if _, err := s.Write([]byte{0}); err != nil {
		t.Fatalf("%s kick write: %v", role, err)
	}
	assertIdentity(t, role, gotID, want)
	_ = s.Close()
}

func setupLibp2pPair(t *testing.T, ctx context.Context) (transport.Transport, transport.Transport) {
	t.Helper()
	server, err := libp2pbackend.New(ctx, libp2pbackend.Options{Bootstrap: []peer.AddrInfo{}})
	if err != nil {
		t.Fatalf("libp2p server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := libp2pbackend.New(ctx, libp2pbackend.Options{Bootstrap: []peer.AddrInfo{}})
	if err != nil {
		t.Fatalf("libp2p client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

func setupHTTP2Pair(t *testing.T, ctx context.Context) (transport.Transport, transport.Transport) {
	t.Helper()
	server, err := h2backend.New(ctx, h2backend.Options{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("http2 server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := h2backend.New(ctx, h2backend.Options{})
	if err != nil {
		t.Fatalf("http2 client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

func setupWebSocketPair(t *testing.T, ctx context.Context) (transport.Transport, transport.Transport) {
	t.Helper()
	server, err := wsbackend.New(ctx, wsbackend.Options{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("ws server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := wsbackend.New(ctx, wsbackend.Options{})
	if err != nil {
		t.Fatalf("ws client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

func setupUnixPair(t *testing.T, ctx context.Context) (transport.Transport, transport.Transport) {
	t.Helper()
	sock := shortSockPath(t)
	server, err := unixbackend.New(ctx, unixbackend.Options{ListenAddr: sock})
	if err != nil {
		t.Fatalf("unix server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := unixbackend.New(ctx, unixbackend.Options{})
	if err != nil {
		t.Fatalf("unix client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

// shortSockPath mirrors vterm/unix_integration_test.go: macOS caps
// sun_path at ~104 bytes, and t.TempDir lands deeper than that on
// darwin. /tmp keeps us under the limit.
func shortSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "m")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, fmt.Sprintf("%d.sock", time.Now().UnixNano()%1_000_000))
}
