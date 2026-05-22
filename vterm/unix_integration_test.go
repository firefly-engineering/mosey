package vterm_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/attach"
	"github.com/firefly-engineering/mosey/auth"
	unixbackend "github.com/firefly-engineering/mosey/transport/unix"
	"github.com/firefly-engineering/mosey/vterm"
)

// TestVterm_Unix_AttachRoundTrip is the libp2p / h2c AttachRoundTrip
// test ported to the unix-socket backend. Same end-to-end shape:
// PSK auth handshake → PTY bytes echo through `cat`. The unix
// backend's per-stream socket model only works for auth correlation
// because the server pulls (uid, pid) from peer credentials; this
// test is the proof.
func TestVterm_Unix_AttachRoundTrip(t *testing.T) {
	t.Parallel()

	psk, err := auth.NewPSKAuth("test-secret")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sockPath := unixTempSockPath(t)
	vtermBackend, err := unixbackend.New(ctx, unixbackend.Options{ListenAddr: sockPath})
	if err != nil {
		t.Fatalf("vterm unix host: %v", err)
	}
	defer func() { _ = vtermBackend.Close() }()
	vtermAuthed := auth.Wrap(vtermBackend, psk)
	vtermAuthed.Serve()

	vtermDone := make(chan error, 1)
	vtermReady := make(chan struct{})
	go func() {
		vtermDone <- vterm.Run(ctx, vterm.Options{Transport: vtermAuthed, Ready: vtermReady}, []string{"cat"})
	}()
	<-vtermReady

	attachBackend, err := unixbackend.New(ctx, unixbackend.Options{}) // client-only
	if err != nil {
		t.Fatalf("attach unix host: %v", err)
	}
	defer func() { _ = attachBackend.Close() }()
	attachAuthed := auth.Wrap(attachBackend, psk)

	endpoints := vtermBackend.Endpoints()
	if len(endpoints) == 0 {
		t.Fatal("unix vterm published no endpoints")
	}
	target := endpoints[0]

	stdinR, stdinW := io.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()
	stdout := &syncBuffer{}

	attachDone := make(chan error, 1)
	go func() {
		attachDone <- attach.Run(ctx, attach.Options{
			Transport: attachAuthed,
			Target:    target,
			Stdin:     stdinR,
			Stdout:    stdout,
		})
	}()

	if _, err := stdinW.Write([]byte("hello-unix\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stdout.String(), "hello-unix") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(stdout.String(), "hello-unix") {
		t.Fatalf("expected %q to appear in attach stdout, got:\n%q", "hello-unix", stdout.String())
	}

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

// unixTempSockPath returns a per-test socket path short enough to
// fit macOS's ~104-byte sun_path cap. The standard t.TempDir lands
// under /var/folders/... on darwin and overflows; the conventional
// escape hatch is to mint a short path under /tmp.
func unixTempSockPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "m")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, fmt.Sprintf("%d.sock", time.Now().UnixNano()%1_000_000))
}
