package vterm_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/firefly-engineering/ship/internal/attach"
	"github.com/firefly-engineering/ship/internal/auth"
	libp2pbackend "github.com/firefly-engineering/ship/internal/transport/libp2p"
	"github.com/firefly-engineering/ship/internal/vterm"
)

// attachClient bundles the bits needed to drive one attach
// session in a test: the host, the auth wrapper, the input pipe,
// and the output capture. Goroutine lifetimes are managed by ctx.
type attachClient struct {
	backend *libp2pbackend.Backend
	authed  *auth.Wrapped
	stdinR  *io.PipeReader
	stdinW  *io.PipeWriter
	out     *syncBuffer
	done    chan error
}

func newAttachClient(t *testing.T, ctx context.Context, target string, secret, label string, caps auth.Capabilities) *attachClient {
	t.Helper()
	psk, err := auth.NewMultiPSKAuth([]auth.NamedSecret{{
		Label: label, Secret: secret, Caps: caps,
	}})
	if err != nil {
		t.Fatalf("attach psk: %v", err)
	}
	backend, err := libp2pbackend.New(ctx, libp2pbackend.Options{Bootstrap: []peer.AddrInfo{}})
	if err != nil {
		t.Fatalf("attach backend: %v", err)
	}
	authed := auth.Wrap(backend, psk)

	stdinR, stdinW := io.Pipe()
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() {
		done <- attach.Run(ctx, attach.Options{
			Transport: authed,
			Target:    target,
			Stdin:     stdinR,
			Stdout:    out,
		})
	}()
	return &attachClient{backend: backend, authed: authed, stdinR: stdinR, stdinW: stdinW, out: out, done: done}
}

func (a *attachClient) Close() {
	_ = a.stdinW.Close()
	_ = a.stdinR.Close()
	_ = a.backend.Close()
}

// newVtermSession boots a vterm + matching server-side auth and
// returns the published target endpoint plus a teardown.
func newVtermSession(t *testing.T, ctx context.Context, mode vterm.Mode, argv []string, secrets []auth.NamedSecret) (target string, done chan error, cleanup func()) {
	t.Helper()
	server, err := auth.NewMultiPSKAuth(secrets)
	if err != nil {
		t.Fatalf("server psk: %v", err)
	}
	backend, err := libp2pbackend.New(ctx, libp2pbackend.Options{Bootstrap: []peer.AddrInfo{}})
	if err != nil {
		t.Fatalf("vterm backend: %v", err)
	}
	authed := auth.Wrap(backend, server)
	authed.Serve()

	done = make(chan error, 1)
	go func() { done <- vterm.Run(ctx, vterm.Options{Transport: authed, Mode: mode}, argv) }()
	time.Sleep(100 * time.Millisecond)

	endpoints := backend.Endpoints()
	if len(endpoints) == 0 {
		t.Fatal("vterm published no endpoints")
	}
	cleanup = func() { _ = backend.Close() }
	return endpoints[0], done, cleanup
}

const testSecret = "owner-pw"

var ownerSecrets = []auth.NamedSecret{{
	Label: auth.LabelOwner, Secret: testSecret,
	Caps: auth.Capabilities{Owner: true, Write: true, Resize: true},
}}

// TestModeSupersede: second attach evicts the first.
func TestMode_Supersede_NewestWins(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target, _, cleanup := newVtermSession(t, ctx, vterm.ModeSupersede, []string{"cat"}, ownerSecrets)
	defer cleanup()

	c1 := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer c1.Close()
	time.Sleep(150 * time.Millisecond)
	if _, err := c1.stdinW.Write([]byte("from-c1\n")); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	if !waitForString(c1.out, "from-c1", 3*time.Second) {
		t.Fatalf("c1 never saw its own echo; got %q", c1.out.String())
	}

	// Second client attaches → c1 should be kicked.
	c2 := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer c2.Close()

	select {
	case <-c1.done:
		// c1 returned — got kicked.
	case <-time.After(3 * time.Second):
		t.Fatal("c1 did not exit after c2 attached (Supersede should kick)")
	}

	// c2 can write and see echo.
	if _, err := c2.stdinW.Write([]byte("from-c2\n")); err != nil {
		t.Fatalf("c2 write: %v", err)
	}
	if !waitForString(c2.out, "from-c2", 3*time.Second) {
		t.Fatalf("c2 never saw its own echo; got %q", c2.out.String())
	}
}

// TestModeExclusive: while a session has any attached client, new
// attaches are refused (stream closes immediately).
func TestMode_Exclusive_RejectsSecondAttach(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target, _, cleanup := newVtermSession(t, ctx, vterm.ModeExclusive, []string{"cat"}, ownerSecrets)
	defer cleanup()

	c1 := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer c1.Close()
	time.Sleep(150 * time.Millisecond)
	if _, err := c1.stdinW.Write([]byte("first\n")); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	if !waitForString(c1.out, "first", 3*time.Second) {
		t.Fatalf("c1 never saw echo; got %q", c1.out.String())
	}

	// c2 attempts to attach; should be admitted only briefly
	// (handshake succeeds), then have its PTY stream closed
	// immediately because the mode refuses.
	c2 := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer c2.Close()
	select {
	case <-c2.done:
		// c2's attach.Run returned because vterm refused.
	case <-time.After(3 * time.Second):
		t.Fatal("c2 did not exit; Exclusive should have refused")
	}

	// c1 still alive and writing.
	if _, err := c1.stdinW.Write([]byte("still-here\n")); err != nil {
		t.Fatalf("c1 second write: %v", err)
	}
	if !waitForString(c1.out, "still-here", 3*time.Second) {
		t.Fatalf("c1 not still attached; out=%q", c1.out.String())
	}
}

// TestModePrimaryObserver: first writer-capable client wins; second
// is forced to observer regardless of its identity caps.
func TestMode_PrimaryObserver_SecondAttachIsObserver(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target, _, cleanup := newVtermSession(t, ctx, vterm.ModePrimaryObserver, []string{"cat"}, ownerSecrets)
	defer cleanup()

	c1 := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer c1.Close()
	c2 := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer c2.Close()
	time.Sleep(200 * time.Millisecond)

	// c1 should be primary; c1's writes echo back.
	if _, err := c1.stdinW.Write([]byte("primary-writes\n")); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	if !waitForString(c1.out, "primary-writes", 3*time.Second) {
		t.Fatalf("c1 never saw its echo: %q", c1.out.String())
	}

	// c2 attempts to write; vterm should drop the bytes.
	if _, err := c2.stdinW.Write([]byte("observer-must-not-echo\n")); err != nil {
		t.Fatalf("c2 write: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // give the PTY time to (not) echo

	combined := c1.out.String() + c2.out.String()
	if strings.Contains(combined, "observer-must-not-echo") {
		t.Errorf("observer's input made it through PTY; combined output: %q", combined)
	}
}

// TestModeMultiWrite: both writer-capable clients can type; bytes
// from both end up in the PTY (interleaved is fine for the test).
func TestMode_MultiWrite_BothCanType(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target, _, cleanup := newVtermSession(t, ctx, vterm.ModeMultiWrite, []string{"cat"}, ownerSecrets)
	defer cleanup()

	c1 := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer c1.Close()
	c2 := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer c2.Close()
	time.Sleep(200 * time.Millisecond)

	if _, err := c1.stdinW.Write([]byte("from-c1-multi\n")); err != nil {
		t.Fatalf("c1 write: %v", err)
	}
	if _, err := c2.stdinW.Write([]byte("from-c2-multi\n")); err != nil {
		t.Fatalf("c2 write: %v", err)
	}

	// Both keystrokes should appear in at least one client's
	// output. Since the PTY broadcasts to all attached clients,
	// each client sees its own bytes (and the other's).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		combined := c1.out.String() + c2.out.String()
		if strings.Contains(combined, "from-c1-multi") && strings.Contains(combined, "from-c2-multi") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("MultiWrite did not deliver both clients' inputs to the PTY; c1=%q c2=%q", c1.out.String(), c2.out.String())
}
