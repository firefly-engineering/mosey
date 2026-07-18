package unix_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/transport"
	unixbackend "github.com/firefly-engineering/mosey/transport/unix"
)

const testProto = "/mosey/test/1.0.0"

// TestBackend_DialEchoesBytes is the round-trip smoke test: server
// handler echoes whatever it reads; client writes a payload,
// half-closes, and asserts the echo comes back. Covers the proto-id
// framing, accept-loop dispatch, and Stream half-close semantics in
// one go.
func TestBackend_DialEchoesBytes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, sockPath := newServer(t, ctx)
	server.Handle(testProto, func(s transport.Stream) {
		defer s.Close()
		_, _ = io.Copy(s, s)
	})

	client, err := unixbackend.New(ctx, unixbackend.Options{})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	defer func() { _ = client.Close() }()

	stream, err := client.Dial(ctx, "unix://"+sockPath, testProto)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer stream.Close()

	const sent = "hello mosey unix"
	if _, err := stream.Write([]byte(sent)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != sent {
		t.Errorf("echo = %q, want %q", got, sent)
	}
}

// TestBackend_CorrelationIDStableAcrossDials proves the server-side
// CorrelationID is the same across two streams from the same caller
// process. This is the property [auth.Wrap] depends on to correlate
// the auth handshake stream with the subsequent application stream.
// For unix the kernel-attested peercreds string is both the
// correlation handle and the RemoteID log tag, so they match.
func TestBackend_CorrelationIDStableAcrossDials(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, sockPath := newServer(t, ctx)

	var (
		seen   []string
		seenMu sync.Mutex
		ready  = make(chan struct{}, 2)
	)
	server.Handle(testProto, func(s transport.Stream) {
		seenMu.Lock()
		// Assert RemoteID mirrors CorrelationID for unix, then track
		// the correlation handle for the stability checks below.
		if s.RemoteID() != s.CorrelationID() {
			t.Errorf("unix RemoteID %q != CorrelationID %q", s.RemoteID(), s.CorrelationID())
		}
		seen = append(seen, s.CorrelationID())
		seenMu.Unlock()
		// Write one byte back so the client can synchronize on it
		// before closing — closing the stream too eagerly races the
		// server's read of the proto prefix.
		_, _ = s.Write([]byte{0x01})
		ready <- struct{}{}
		_, _ = io.Copy(io.Discard, s)
		_ = s.Close()
	})

	client, err := unixbackend.New(ctx, unixbackend.Options{})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	defer func() { _ = client.Close() }()

	for i := 0; i < 2; i++ {
		s, err := client.Dial(ctx, "unix://"+sockPath, testProto)
		if err != nil {
			t.Fatalf("Dial #%d: %v", i, err)
		}
		var ack [1]byte
		if _, err := io.ReadFull(s, ack[:]); err != nil {
			t.Fatalf("read ack #%d: %v", i, err)
		}
		_ = s.Close()
		select {
		case <-ready:
		case <-time.After(2 * time.Second):
			t.Fatalf("handler #%d didn't fire", i)
		}
	}

	seenMu.Lock()
	defer seenMu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("seen %d CorrelationIDs, want 2: %v", len(seen), seen)
	}
	if seen[0] != seen[1] {
		t.Errorf("CorrelationID changed between dials: %q vs %q", seen[0], seen[1])
	}
	if !strings.HasPrefix(seen[0], "unix:uid=") || !strings.Contains(seen[0], ":pid=") {
		t.Errorf("CorrelationID shape = %q, want unix:uid=N:pid=M", seen[0])
	}
}

// TestBackend_UnregisteredProtocolClosesQuickly verifies the server
// closes a connection whose proto-id prefix doesn't match any
// registered handler. Mirrors how libp2p surfaces "protocol not
// supported" — silent close, no error code — so attach's graceful-
// degradation path keeps working with this backend too.
func TestBackend_UnregisteredProtocolClosesQuickly(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, sockPath := newServer(t, ctx) // no Handle registration

	client, err := unixbackend.New(ctx, unixbackend.Options{})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	defer func() { _ = client.Close() }()

	stream, err := client.Dial(ctx, "unix://"+sockPath, "/mosey/unknown/1.0.0")
	if err != nil {
		// Some kernels surface the server-side close as a dial error.
		// Either form is acceptable; the contract is just that the
		// client doesn't end up with an open stream sitting on an
		// unhandled protocol.
		return
	}
	defer stream.Close()

	// Read should return EOF promptly because the server closed.
	if _, err := io.ReadAll(stream); err != nil && err != io.EOF {
		// A "use of closed network connection" / "connection reset"
		// is fine — we only fail if the server kept the stream alive.
		return
	}
}

// TestBackend_EndpointsAdvertisesScheme covers the Multi-router
// contract: Endpoints() must return URIs whose scheme matches
// Schemes() so a Multi aggregator can dispatch outbound dials back
// to this backend.
func TestBackend_EndpointsAdvertisesScheme(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, sockPath := newServer(t, ctx)
	endpoints := server.Endpoints()
	if len(endpoints) != 1 {
		t.Fatalf("Endpoints = %v, want exactly one entry", endpoints)
	}
	want := "unix://" + sockPath
	if endpoints[0] != want {
		t.Errorf("Endpoints[0] = %q, want %q", endpoints[0], want)
	}
	schemes := server.Schemes()
	if len(schemes) != 1 || schemes[0] != "unix" {
		t.Errorf("Schemes = %v, want [unix]", schemes)
	}
}

// TestBackend_StaleSocketIsReplaced ensures New(ListenAddr=X) works
// even when X already exists as a stale socket file from a crashed
// prior launcher. Without the os.Remove, ListenUnix would return
// EADDRINUSE.
func TestBackend_StaleSocketIsReplaced(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sockPath := shortSockPath(t)
	if err := os.WriteFile(sockPath, []byte("stale"), 0o600); err != nil {
		t.Fatalf("seed stale file: %v", err)
	}
	server, err := unixbackend.New(ctx, unixbackend.Options{ListenAddr: sockPath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = server.Close() }()
	if got := server.Endpoints(); len(got) != 1 {
		t.Errorf("Endpoints after stale-replace = %v, want one entry", got)
	}
}

// TestBackend_DialRejectsEmptyProto refuses an empty protocol id at
// the client. Mostly a guardrail — the wire prefix can't carry an
// empty string and have the server distinguish it from a bogus
// connection that just sent the varint and hung up.
func TestBackend_DialRejectsEmptyProto(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, sockPath := newServer(t, ctx)
	client, err := unixbackend.New(ctx, unixbackend.Options{})
	if err != nil {
		t.Fatalf("client New: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Dial(ctx, "unix://"+sockPath, "")
	if err == nil {
		t.Fatal("Dial with empty proto must error")
	}
}

// newServer is the shared setup: bind a backend on a per-test
// temporary socket path, register cleanup, return the backend +
// path.
func newServer(t *testing.T, ctx context.Context) (*unixbackend.Backend, string) {
	t.Helper()
	sockPath := shortSockPath(t)
	b, err := unixbackend.New(ctx, unixbackend.Options{ListenAddr: sockPath})
	if err != nil {
		t.Fatalf("server New: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, sockPath
}

// shortSockPath returns a temp socket path under /tmp short enough
// to fit macOS's ~104-byte sun_path cap. t.TempDir() lands under
// /var/folders/... on darwin which routinely overflows that limit;
// /tmp is the conventional short-path escape hatch for unix-socket
// tests on macOS. Cleanup removes the parent directory.
func shortSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "m")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, fmt.Sprintf("%d.sock", time.Now().UnixNano()%1_000_000))
}
