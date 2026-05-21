package transport_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/firefly-engineering/mosey/internal/transport"
)

// fakeTransport is a hand-rolled stub implementing [transport.Transport]
// for the Multi tests. It records every Handle / Unhandle / Dial call
// so assertions can verify the fan-out behavior without spinning a
// real backend.
type fakeTransport struct {
	schemes   []string
	endpoints []string

	mu       sync.Mutex
	handlers map[string]transport.Handler
	dialed   []dialCall
	closed   bool
	dialErr  error
}

type dialCall struct{ endpoint, protocol string }

func newFake(schemes ...string) *fakeTransport {
	return &fakeTransport{schemes: schemes, handlers: map[string]transport.Handler{}}
}

func (f *fakeTransport) Schemes() []string   { return f.schemes }
func (f *fakeTransport) Endpoints() []string { return f.endpoints }

func (f *fakeTransport) Handle(protocol string, h transport.Handler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[protocol] = h
}

func (f *fakeTransport) Unhandle(protocol string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.handlers, protocol)
}

func (f *fakeTransport) Dial(_ context.Context, endpoint, protocol string) (transport.Stream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dialed = append(f.dialed, dialCall{endpoint: endpoint, protocol: protocol})
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	return nil, errors.New("fake: Dial not implemented")
}

func (f *fakeTransport) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func TestMulti_RejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := transport.Multi(); err == nil {
		t.Fatal("Multi() with no backends must error")
	}
}

func TestMulti_RejectsDuplicateScheme(t *testing.T) {
	t.Parallel()
	a := newFake("libp2p")
	b := newFake("libp2p")
	if _, err := transport.Multi(a, b); err == nil {
		t.Fatal("two backends claiming the same scheme must error")
	}
}

func TestMulti_AcceptsDistinctSchemes(t *testing.T) {
	t.Parallel()
	libp2p := newFake("libp2p")
	https := newFake("https")
	m, err := transport.Multi(libp2p, https)
	if err != nil {
		t.Fatalf("Multi: %v", err)
	}
	schemes := m.Schemes()
	if len(schemes) != 2 {
		t.Errorf("Schemes() = %v, want 2 entries", schemes)
	}
}

func TestMulti_HandleFansOut(t *testing.T) {
	t.Parallel()
	a := newFake("libp2p")
	b := newFake("https")
	m, err := transport.Multi(a, b)
	if err != nil {
		t.Fatalf("Multi: %v", err)
	}

	h := transport.Handler(func(transport.Stream) {})
	m.Handle("/ship/pty/1.0.0", h)

	if _, ok := a.handlers["/ship/pty/1.0.0"]; !ok {
		t.Error("backend a did not receive the handler")
	}
	if _, ok := b.handlers["/ship/pty/1.0.0"]; !ok {
		t.Error("backend b did not receive the handler")
	}
}

func TestMulti_UnhandleFansOut(t *testing.T) {
	t.Parallel()
	a := newFake("libp2p")
	b := newFake("https")
	m, _ := transport.Multi(a, b)
	m.Handle("/ship/pty/1.0.0", func(transport.Stream) {})
	m.Unhandle("/ship/pty/1.0.0")
	if _, ok := a.handlers["/ship/pty/1.0.0"]; ok {
		t.Error("backend a still has the handler")
	}
	if _, ok := b.handlers["/ship/pty/1.0.0"]; ok {
		t.Error("backend b still has the handler")
	}
}

func TestMulti_EndpointsUnion(t *testing.T) {
	t.Parallel()
	a := newFake("libp2p")
	a.endpoints = []string{"libp2p:///a", "libp2p:///b"}
	b := newFake("https")
	b.endpoints = []string{"https://host/c"}
	m, _ := transport.Multi(a, b)
	got := m.Endpoints()
	if len(got) != 3 {
		t.Errorf("Endpoints union = %v (len %d), want 3 entries", got, len(got))
	}
}

func TestMulti_DialRoutesByScheme(t *testing.T) {
	t.Parallel()
	a := newFake("libp2p")
	b := newFake("https")
	m, _ := transport.Multi(a, b)

	_, _ = m.Dial(context.Background(), "https://host/x", "/ship/pty/1.0.0")
	if len(a.dialed) != 0 {
		t.Errorf("libp2p backend received a Dial it shouldn't have: %v", a.dialed)
	}
	if len(b.dialed) != 1 || b.dialed[0].endpoint != "https://host/x" {
		t.Errorf("https backend Dial = %v, want exactly one to https://host/x", b.dialed)
	}
}

func TestMulti_DialBareMultiaddrRoutesToLibp2p(t *testing.T) {
	t.Parallel()
	a := newFake("libp2p")
	b := newFake("https")
	m, _ := transport.Multi(a, b)

	_, _ = m.Dial(context.Background(), "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWtest", "/ship/pty/1.0.0")
	if len(a.dialed) != 1 {
		t.Errorf("libp2p backend should have received the bare-multiaddr Dial; got %v", a.dialed)
	}
}

func TestMulti_DialUnknownScheme(t *testing.T) {
	t.Parallel()
	a := newFake("libp2p")
	m, _ := transport.Multi(a)
	_, err := m.Dial(context.Background(), "ftp://host/x", "/ship/pty/1.0.0")
	if err == nil {
		t.Fatal("unknown scheme must return an error")
	}
	if !errors.Is(err, transport.ErrUnsupportedScheme) {
		t.Errorf("err = %v, want wrap of ErrUnsupportedScheme", err)
	}
	if !strings.Contains(err.Error(), "ftp") {
		t.Errorf("err message should mention the scheme; got %v", err)
	}
}

func TestMulti_CloseFansOut(t *testing.T) {
	t.Parallel()
	a := newFake("libp2p")
	b := newFake("https")
	m, _ := transport.Multi(a, b)
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !a.closed || !b.closed {
		t.Errorf("Close fan-out failed: a.closed=%v b.closed=%v", a.closed, b.closed)
	}
}
