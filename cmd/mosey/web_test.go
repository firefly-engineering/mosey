package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/firefly-engineering/mosey/auth"
	unixbackend "github.com/firefly-engineering/mosey/transport/unix"
	"github.com/firefly-engineering/mosey/vterm"
)

// TestWebGateway_BridgeRoundTrip stands up an in-process vterm host
// running `cat` over a unix socket, points the web gateway at it, and
// drives a real browser-style WebSocket through the gateway: binary
// frames in, echoed binary frames out. Proves the browser↔gateway↔host
// bridge end to end (auth handshake, PTY pump, resize control).
func TestWebGateway_BridgeRoundTrip(t *testing.T) {
	psk, err := auth.NewPSKAuth("web-secret")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Host: vterm over a unix socket running `cat` (echoes input).
	sock := filepath.Join("/tmp", fmt.Sprintf("mosey-web-%d.sock", os.Getpid()))
	defer func() { _ = os.Remove(sock) }()
	hostBackend, err := unixbackend.New(ctx, unixbackend.Options{ListenAddr: sock})
	if err != nil {
		t.Fatalf("host backend: %v", err)
	}
	defer func() { _ = hostBackend.Close() }()
	hostAuthed := auth.Wrap(hostBackend, psk)
	hostAuthed.Serve()

	ready := make(chan struct{})
	go func() { _ = vterm.Run(ctx, vterm.Options{Transport: hostAuthed, Ready: ready}, []string{"cat"}) }()
	<-ready

	endpoints := hostBackend.Endpoints()
	if len(endpoints) == 0 {
		t.Fatal("host published no endpoints")
	}

	// Gateway: client-only unix backend wrapped with the same PSK,
	// pointed at the host endpoint.
	gwClient, err := unixbackend.New(ctx, unixbackend.Options{})
	if err != nil {
		t.Fatalf("gateway client backend: %v", err)
	}
	defer func() { _ = gwClient.Close() }()
	gw := &webGateway{
		transport: auth.Wrap(gwClient, psk),
		target:    endpoints[0],
		logger:    newLogger(os.Stderr, "error"),
	}

	srv := httptest.NewServer(gw.mux())
	defer srv.Close()

	// The static page is served.
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "mosey · web terminal") {
		t.Fatalf("GET / = %d, body lacks title: %.80q", resp.StatusCode, body)
	}

	// Browser-style WebSocket to /ws.
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Accumulate output frames in the background.
	var mu sync.Mutex
	var out strings.Builder
	go func() {
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.BinaryMessage {
				mu.Lock()
				out.Write(data)
				mu.Unlock()
			}
		}
	}()

	// Resize (text control), then input (binary).
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","cols":80,"rows":24}`)); err != nil {
		t.Fatalf("ws resize: %v", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("hello-web\n")); err != nil {
		t.Fatalf("ws write: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := out.String()
		mu.Unlock()
		if strings.Contains(got, "hello-web") {
			return // success
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	got := out.String()
	mu.Unlock()
	t.Fatalf("did not observe echoed input; got %.200q", got)
}
