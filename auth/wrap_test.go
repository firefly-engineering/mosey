package auth

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/firefly-engineering/mosey/api"
	"github.com/firefly-engineering/mosey/transport"
)

// fakeStream is a minimal [transport.Stream] whose CorrelationID is
// fixed by the test. Read returns EOF; Write and the rest are inert
// except that Close is observable.
type fakeStream struct {
	correlation string
	remote      string

	mu     sync.Mutex
	closed bool
}

func (s *fakeStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (s *fakeStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *fakeStream) CloseWrite() error           { return nil }
func (s *fakeStream) RemoteID() string            { return s.remote }
func (s *fakeStream) CorrelationID() string       { return s.correlation }

func (s *fakeStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *fakeStream) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// fakeInner is a [transport.Transport] that only records the
// handlers registered on it, so a test can deliver a stream of its
// choosing to the handler auth.Wrap installed.
type fakeInner struct {
	mu       sync.Mutex
	handlers map[string]transport.Handler
}

func newFakeInner() *fakeInner {
	return &fakeInner{handlers: map[string]transport.Handler{}}
}

func (f *fakeInner) Schemes() []string   { return nil }
func (f *fakeInner) Endpoints() []string { return nil }
func (f *fakeInner) Handle(proto string, h transport.Handler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[proto] = h
}
func (f *fakeInner) Unhandle(proto string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.handlers, proto)
}
func (f *fakeInner) Dial(context.Context, string, string) (transport.Stream, error) {
	return nil, io.EOF
}
func (f *fakeInner) Close() error { return nil }

func (f *fakeInner) deliver(proto string, s transport.Stream) {
	f.mu.Lock()
	h := f.handlers[proto]
	f.mu.Unlock()
	if h != nil {
		h(s)
	}
}

// fakeAuth is an [Authenticator] whose ServerHandshake always
// succeeds with a fixed identity.
type fakeAuth struct{ id Identity }

func (a fakeAuth) Name() string { return "fake" }
func (a fakeAuth) ClientHandshake(context.Context, io.ReadWriteCloser) (Identity, error) {
	return a.id, nil
}
func (a fakeAuth) ServerHandshake(context.Context, io.ReadWriteCloser) (Identity, error) {
	return a.id, nil
}

// TestWrap_RefusesEmptyCorrelationOnAppStream proves the fail-closed
// guard: an application stream whose CorrelationID is empty is closed
// and never reaches the wrapped handler, even after a successful
// handshake stored an identity under a real key.
func TestWrap_RefusesEmptyCorrelationOnAppStream(t *testing.T) {
	inner := newFakeInner()
	w := Wrap(inner, fakeAuth{id: Identity{Label: "owner"}})
	w.Serve()

	// A real handshake stores an identity under a non-empty key.
	w.Handle("/app", func(transport.Stream) {
		t.Error("app handler ran for an empty-correlation stream")
	})
	inner.deliver(api.ProtoAuth, &fakeStream{correlation: "peer-1"})

	// An application stream with no correlation must be refused.
	empty := &fakeStream{correlation: ""}
	inner.deliver("/app", empty)
	if !empty.isClosed() {
		t.Error("empty-correlation app stream was not closed")
	}
}

// TestWrap_RefusesEmptyCorrelationOnHandshake proves the symmetric
// guard: a handshake that succeeds but yields an empty correlation
// stores nothing, so a later stream sharing that empty key is still
// refused rather than inheriting the identity.
func TestWrap_RefusesEmptyCorrelationOnHandshake(t *testing.T) {
	inner := newFakeInner()
	w := Wrap(inner, fakeAuth{id: Identity{Label: "owner"}})
	w.Serve()

	// Handshake succeeds but the stream can't correlate — store nothing.
	inner.deliver(api.ProtoAuth, &fakeStream{correlation: ""})

	w.Handle("/app", func(transport.Stream) {
		t.Error("app handler ran despite no identity being stored")
	})
	app := &fakeStream{correlation: ""}
	inner.deliver("/app", app)
	if !app.isClosed() {
		t.Error("app stream was not closed after empty-correlation handshake")
	}
}

// TestWrap_CorrelatesMatchingStream is the positive control: an app
// stream whose CorrelationID matches a prior handshake reaches the
// handler carrying the stored identity.
func TestWrap_CorrelatesMatchingStream(t *testing.T) {
	inner := newFakeInner()
	w := Wrap(inner, fakeAuth{id: Identity{Label: "owner"}})
	w.Serve()

	inner.deliver(api.ProtoAuth, &fakeStream{correlation: "peer-1"})

	var got Identity
	ran := false
	w.Handle("/app", func(s transport.Stream) {
		ran = true
		got = IdentityOf(s)
	})
	inner.deliver("/app", &fakeStream{correlation: "peer-1"})
	if !ran {
		t.Fatal("app handler did not run for a correlated stream")
	}
	if got.Label != "owner" {
		t.Errorf("identity Label = %q, want owner", got.Label)
	}
}
