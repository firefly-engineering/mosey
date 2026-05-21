package vterm_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/firefly-engineering/ship/internal/attach"
	"github.com/firefly-engineering/ship/internal/auth"
	libp2pbackend "github.com/firefly-engineering/ship/internal/transport/libp2p"
	"github.com/firefly-engineering/ship/internal/vterm"
)

// TestVterm_AttachRoundTrip stands up a vterm host running `cat`
// and a separate attach host on the same loopback interface, then
// drives bytes through the bidi PTY pipe and asserts they round-
// trip back. Exercises the full stack: PSK auth, libp2p TCP
// transport, /ship/pty stream handler, PTY ownership.
func TestVterm_AttachRoundTrip(t *testing.T) {
	t.Parallel()

	const secret = "test-secret"
	psk, err := auth.NewPSKAuth(secret)
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Host A: the vterm.
	vtermHost, err := libp2pbackend.New(ctx, libp2pbackend.Options{
		Auth:      psk,
		Bootstrap: []peer.AddrInfo{},
	})
	if err != nil {
		t.Fatalf("vterm host: %v", err)
	}
	defer func() { _ = vtermHost.Close() }()

	// Run `cat` under the vterm. Echoes its input back as output,
	// so anything attach sends should reappear on attach's stdout.
	vtermDone := make(chan error, 1)
	go func() {
		vtermDone <- vterm.Run(ctx, vterm.Options{Host: vtermHost.Host()}, []string{"cat"})
	}()

	// Wait a beat for vterm.Run to register the stream handler.
	// Without this, attach can race and open the stream before the
	// handler is up, which libp2p reports as "protocol not
	// supported". 50ms is plenty for in-process.
	time.Sleep(100 * time.Millisecond)

	// Host B: the attach client.
	attachHost, err := libp2pbackend.New(ctx, libp2pbackend.Options{
		Auth:      psk,
		Bootstrap: []peer.AddrInfo{},
	})
	if err != nil {
		t.Fatalf("attach host: %v", err)
	}
	defer func() { _ = attachHost.Close() }()

	target := peer.AddrInfo{
		ID:    vtermHost.Host().ID(),
		Addrs: vtermHost.Host().Addrs(),
	}

	// stdinR is what attach reads (we write bytes here to simulate
	// the user typing); stdoutW is where attach writes (we read
	// back to assert what the vterm echoed).
	stdinR, stdinW := io.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()

	stdout := &syncBuffer{}

	attachDone := make(chan error, 1)
	go func() {
		attachDone <- attach.Run(ctx, attach.Options{
			Host:   attachHost.Host(),
			Target: target,
			Stdin:  stdinR,
			Stdout: stdout,
		})
	}()

	// Send a line, wait for cat to echo it back via the PTY.
	const sent = "hello-ship\n"
	if _, err := stdinW.Write([]byte(sent)); err != nil {
		t.Fatalf("write stdin: %v", err)
	}

	// PTY in cooked mode echoes input + appends the cat output. So
	// we expect to see at least "hello-ship" come back on stdout.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stdout.String(), "hello-ship") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(stdout.String(), "hello-ship") {
		t.Fatalf("expected %q to appear in attach stdout, got:\n%q", "hello-ship", stdout.String())
	}

	// Closing stdin makes cat exit (it's reading from the PTY which
	// gets EOF when the PTY master is closed; trickier here since
	// we don't have a clean way to half-close from attach. Just
	// cancel the ctx to tear everything down.)
	cancel()

	select {
	case <-attachDone:
	case <-time.After(2 * time.Second):
		t.Error("attach.Run did not return within 2s of cancel")
	}
	select {
	case <-vtermDone:
	case <-time.After(2 * time.Second):
		t.Error("vterm.Run did not return within 2s of cancel")
	}
}

// syncBuffer is a tiny thread-safe buffer used as attach's stdout
// in the test. Concurrent writes from the io.Copy goroutine and
// reads from the assertion loop need locking; bytes.Buffer isn't
// safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer

	// closed is set when the writer side has finished — currently
	// unused but kept so callers can plumb it in later.
	closed atomic.Bool
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
