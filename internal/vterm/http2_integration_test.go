package vterm_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/internal/attach"
	"github.com/firefly-engineering/mosey/internal/auth"
	httpbackend "github.com/firefly-engineering/mosey/internal/transport/http2"
	"github.com/firefly-engineering/mosey/internal/vterm"
)

// TestVterm_HTTP2_AttachRoundTrip is the libp2p AttachRoundTrip
// test ported to the h2c backend. End-to-end exercise of the new
// transport: auth handshake on /ship/auth/, PTY bytes through
// /ship/pty/, all over a single HTTP/2 TCP connection.
func TestVterm_HTTP2_AttachRoundTrip(t *testing.T) {
	t.Parallel()

	psk, err := auth.NewPSKAuth("test-secret")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	vtermBackend, err := httpbackend.New(ctx, httpbackend.Options{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("vterm h2c host: %v", err)
	}
	defer func() { _ = vtermBackend.Close() }()
	vtermAuthed := auth.Wrap(vtermBackend, psk)
	vtermAuthed.Serve()

	vtermDone := make(chan error, 1)
	go func() {
		vtermDone <- vterm.Run(ctx, vterm.Options{Transport: vtermAuthed}, []string{"cat"})
	}()
	time.Sleep(100 * time.Millisecond)

	attachBackend, err := httpbackend.New(ctx, httpbackend.Options{})
	if err != nil {
		t.Fatalf("attach h2c host: %v", err)
	}
	defer func() { _ = attachBackend.Close() }()
	attachAuthed := auth.Wrap(attachBackend, psk)

	endpoints := vtermBackend.Endpoints()
	if len(endpoints) == 0 {
		t.Fatal("h2c vterm published no endpoints")
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

	if _, err := stdinW.Write([]byte("hello-h2c\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stdout.String(), "hello-h2c") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(stdout.String(), "hello-h2c") {
		t.Fatalf("expected %q to appear in attach stdout, got:\n%q", "hello-h2c", stdout.String())
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
