package libp2p_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	libp2pgo "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/firefly-engineering/mosey/transport"
	libp2pbackend "github.com/firefly-engineering/mosey/transport/libp2p"
)

// TestBYOHost confirms that a caller-supplied host shares one
// libp2p identity with the mosey backend, that a non-mosey protocol
// registered directly on the host coexists with a mosey-registered
// handler, and that closing the backend leaves the caller's host
// usable. This is the shape shepherd needs to run forwarder RPCs
// on the same peer id that serves /mosey/pty/.
func TestBYOHost(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Caller-owned host. Two of them: a server and a client. Both
	// stay loopback-only and skip bootstrap to keep the test cheap
	// and offline.
	serverHost := newTestHost(t)
	t.Cleanup(func() { _ = serverHost.Close() })
	clientHost := newTestHost(t)
	t.Cleanup(func() { _ = clientHost.Close() })

	// Register a non-mosey protocol directly on the server host,
	// before mosey gets near it. After the backend closes we'll
	// dial this same protocol to confirm the host is still alive.
	const extraProto = "/test/echo/1"
	serverHost.SetStreamHandler(protocol.ID(extraProto), func(s network.Stream) {
		defer func() { _ = s.Close() }()
		_, _ = io.Copy(s, s)
	})

	serverBackend, err := libp2pbackend.New(ctx, libp2pbackend.Options{Host: serverHost})
	if err != nil {
		t.Fatalf("server backend: %v", err)
	}
	clientBackend, err := libp2pbackend.New(ctx, libp2pbackend.Options{Host: clientHost})
	if err != nil {
		t.Fatalf("client backend: %v", err)
	}

	const mosheyProto = "/mosey/pty/1.0.0"
	gotMosey := make(chan string, 1)
	serverBackend.Handle(mosheyProto, func(s transport.Stream) {
		defer func() { _ = s.Close() }()
		buf := make([]byte, 64)
		n, _ := s.Read(buf)
		gotMosey <- string(buf[:n])
	})

	// Connect client → server out-of-band so Dial doesn't need to
	// resolve via DHT (we skipped bootstrap).
	if err := clientHost.Connect(ctx, peer.AddrInfo{
		ID:    serverHost.ID(),
		Addrs: serverHost.Addrs(),
	}); err != nil {
		t.Fatalf("client connect: %v", err)
	}

	endpoints := serverBackend.Endpoints()
	if len(endpoints) == 0 {
		t.Fatal("server published no endpoints")
	}

	// Round-trip on the mosey protocol.
	s, err := clientBackend.Dial(ctx, endpoints[0], mosheyProto)
	if err != nil {
		t.Fatalf("dial mosey proto: %v", err)
	}
	if _, err := s.Write([]byte("hi-mosey")); err != nil {
		t.Fatalf("write mosey: %v", err)
	}
	if hc, ok := s.(transport.HalfCloser); ok {
		_ = hc.CloseWrite()
	}
	select {
	case got := <-gotMosey:
		if got != "hi-mosey" {
			t.Fatalf("mosey handler got %q, want %q", got, "hi-mosey")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mosey handler never fired")
	}
	_ = s.Close()

	// Round-trip on the caller's non-mosey protocol over the *same*
	// host pair, before backend.Close.
	roundTrip(t, ctx, clientHost, serverHost.ID(), extraProto, "hi-extra")

	// Close both mosey backends. The caller-owned hosts must still
	// be alive and the extra protocol still reachable.
	if err := serverBackend.Close(); err != nil {
		t.Fatalf("server backend close: %v", err)
	}
	if err := clientBackend.Close(); err != nil {
		t.Fatalf("client backend close: %v", err)
	}
	if serverHost.Network().Connectedness(clientHost.ID()) == network.NotConnected &&
		clientHost.Network().Connectedness(serverHost.ID()) == network.NotConnected {
		t.Fatal("backend.Close tore the caller's host connection down")
	}
	roundTrip(t, ctx, clientHost, serverHost.ID(), extraProto, "still-here")
}

// TestBYOHost_RejectsAmbiguousConfig confirms that setting Host
// together with any of the construction-only fields fails fast,
// rather than silently ignoring them.
func TestBYOHost_RejectsAmbiguousConfig(t *testing.T) {
	t.Parallel()

	h := newTestHost(t)
	t.Cleanup(func() { _ = h.Close() })

	cases := []struct {
		name string
		opts libp2pbackend.Options
	}{
		{"with-listen-addrs", libp2pbackend.Options{Host: h, ListenAddrs: nil /* set below */}},
		{"with-empty-bootstrap", libp2pbackend.Options{Host: h, Bootstrap: []peer.AddrInfo{}}},
	}
	// ListenAddrs needs a non-nil multiaddr slice to count as "set"
	// per the Options semantics; build it once.
	cases[0].opts.ListenAddrs = h.Addrs()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := libp2pbackend.New(context.Background(), tc.opts)
			if err == nil {
				t.Fatal("expected ambiguous-config error, got nil")
			}
		})
	}
}

func newTestHost(t *testing.T) host.Host {
	t.Helper()
	h, err := libp2pgo.New(
		libp2pgo.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2pgo.DisableRelay(),
	)
	if err != nil {
		t.Fatalf("libp2p.New: %v", err)
	}
	return h
}

func roundTrip(t *testing.T, ctx context.Context, from host.Host, to peer.ID, proto, msg string) {
	t.Helper()
	s, err := from.NewStream(ctx, to, protocol.ID(proto))
	if err != nil {
		t.Fatalf("open %s: %v", proto, err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.Write([]byte(msg)); err != nil {
		t.Fatalf("write %s: %v", proto, err)
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatalf("close-write %s: %v", proto, err)
	}
	buf := make([]byte, len(msg)+8)
	n, err := io.ReadFull(s, buf[:len(msg)])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read %s: %v", proto, err)
	}
	if string(buf[:n]) != msg {
		t.Fatalf("echo %s: got %q, want %q", proto, buf[:n], msg)
	}
}
