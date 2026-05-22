package vterm_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/attach"
	"github.com/firefly-engineering/mosey/auth"
	wsbackend "github.com/firefly-engineering/mosey/transport/websocket"
	"github.com/firefly-engineering/mosey/vterm"
)

// TestVterm_WebSocket_AttachRoundTrip is the libp2p / h2c / unix
// AttachRoundTrip test ported to the WebSocket backend. Same shape:
// PSK auth handshake → PTY bytes echo through `cat`. The WebSocket
// backend's per-stream connection model only works for auth
// correlation because the dialer offers a stable per-process token
// in `Sec-WebSocket-Protocol` and the server uses it as RemoteID;
// this test is the proof.
func TestVterm_WebSocket_AttachRoundTrip(t *testing.T) {
	t.Parallel()

	psk, err := auth.NewPSKAuth("test-secret")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	vtermBackend, err := wsbackend.New(ctx, wsbackend.Options{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("vterm ws host: %v", err)
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

	attachBackend, err := wsbackend.New(ctx, wsbackend.Options{}) // client-only
	if err != nil {
		t.Fatalf("attach ws host: %v", err)
	}
	defer func() { _ = attachBackend.Close() }()
	attachAuthed := auth.Wrap(attachBackend, psk)

	endpoints := vtermBackend.Endpoints()
	if len(endpoints) == 0 {
		t.Fatal("ws vterm published no endpoints")
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

	if _, err := stdinW.Write([]byte("hello-ws\n")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stdout.String(), "hello-ws") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(stdout.String(), "hello-ws") {
		t.Fatalf("expected %q to appear in attach stdout, got:\n%q", "hello-ws", stdout.String())
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
