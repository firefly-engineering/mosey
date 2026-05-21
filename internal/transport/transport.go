package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
)

// ErrUnsupportedScheme is returned by [Transport.Dial] when the
// supplied endpoint's URI scheme isn't one this transport handles.
// [Multi] surfaces it when no aggregated backend claims the scheme.
var ErrUnsupportedScheme = errors.New("transport: endpoint scheme not supported by this transport")

// Stream is one bidi byte channel between two peers. Backends:
// libp2p multiplexer streams, HTTP/2 streams, raw TCP+TLS, WebSocket.
// Read / Write / Close obey [io.ReadWriteCloser] semantics.
type Stream interface {
	io.ReadWriteCloser

	// CloseWrite half-closes the local write side so the peer sees
	// a clean EOF on its read. Optional: backends that can't model
	// half-close (raw TCP without framing) return [ErrUnsupported].
	CloseWrite() error
}

// ErrUnsupported is returned by optional [Stream] methods when the
// underlying transport can't honor the request (e.g. CloseWrite on
// a transport without half-close semantics).
var ErrUnsupported = errors.New("transport: operation not supported by this backend")

// Handler is invoked for each inbound stream of a registered
// protocol. The handler owns the stream — it must Close it before
// returning. Multiple handlers may run concurrently; backends do
// not serialize them.
type Handler func(Stream)

// Transport is the minimum surface ship needs from a network
// backend. Implementations exist in [internal/transport/libp2p];
// future backends (http2, websocket, unix) plug in via the same
// shape.
//
// Implementations must be safe for concurrent use. The lifecycle
// of registered handlers and active streams is bounded by Close —
// once Close returns, no more handler callbacks fire and all
// dialed streams have been torn down.
type Transport interface {
	// Schemes returns the URI schemes this transport claims when
	// routed through a [Multi] aggregator. Examples: "libp2p",
	// "https", "ws". Each backend's schemes must be unique within
	// a Multi.
	Schemes() []string

	// Endpoints returns the dialable addresses this transport is
	// currently listening on, in URI form ("libp2p:///p2p/12D3...",
	// "https://host:443/ship", "ws://..."). Empty for client-only
	// configurations (a transport with no listener).
	Endpoints() []string

	// Handle registers handler for inbound streams of protocol.
	// Replaces any previously-registered handler for the same
	// protocol; backends that can't replace atomically may briefly
	// drop streams during a swap.
	Handle(protocol string, handler Handler)

	// Unhandle removes a previously-registered handler. A no-op
	// when no handler was registered.
	Unhandle(protocol string)

	// Dial opens a new bidirectional stream to endpoint, speaking
	// protocol. The endpoint format is backend-specific (a
	// libp2p multiaddr, an HTTPS URL, etc.); aggregating
	// transports route by URI scheme.
	Dial(ctx context.Context, endpoint, protocol string) (Stream, error)

	// Close tears down listeners, cancels active handler
	// invocations, and closes outstanding streams. Returns the
	// first error encountered during teardown, if any.
	Close() error
}

// Multi aggregates several backends behind a single [Transport]
// surface. Handle / Unhandle fan out to every backend; Endpoints
// unions all listened addresses; Dial routes by URI scheme to the
// backend that claims it; Close tears every backend down.
//
// Returns an error if two backends claim the same scheme — that's
// a config bug, not a runtime fault.
func Multi(backends ...Transport) (Transport, error) {
	if len(backends) == 0 {
		return nil, errors.New("transport: Multi requires at least one backend")
	}
	m := &multi{
		backends: backends,
		schemes:  map[string]Transport{},
		handlers: map[string]Handler{},
	}
	for _, b := range backends {
		for _, s := range b.Schemes() {
			if existing, dup := m.schemes[s]; dup && existing != b {
				return nil, fmt.Errorf("transport: scheme %q claimed by two backends", s)
			}
			m.schemes[s] = b
		}
	}
	return m, nil
}

type multi struct {
	backends []Transport
	schemes  map[string]Transport

	mu       sync.Mutex
	handlers map[string]Handler
}

func (m *multi) Schemes() []string {
	out := make([]string, 0, len(m.schemes))
	for s := range m.schemes {
		out = append(out, s)
	}
	return out
}

func (m *multi) Endpoints() []string {
	var out []string
	for _, b := range m.backends {
		out = append(out, b.Endpoints()...)
	}
	return out
}

func (m *multi) Handle(protocol string, handler Handler) {
	m.mu.Lock()
	m.handlers[protocol] = handler
	m.mu.Unlock()
	for _, b := range m.backends {
		b.Handle(protocol, handler)
	}
}

func (m *multi) Unhandle(protocol string) {
	m.mu.Lock()
	delete(m.handlers, protocol)
	m.mu.Unlock()
	for _, b := range m.backends {
		b.Unhandle(protocol)
	}
}

func (m *multi) Dial(ctx context.Context, endpoint, protocol string) (Stream, error) {
	scheme, err := schemeOf(endpoint)
	if err != nil {
		return nil, fmt.Errorf("transport: dial: %w", err)
	}
	backend, ok := m.schemes[scheme]
	if !ok {
		return nil, fmt.Errorf("%w: scheme %q (have %v)", ErrUnsupportedScheme, scheme, m.schemes)
	}
	return backend.Dial(ctx, endpoint, protocol)
}

func (m *multi) Close() error {
	var errs []error
	for _, b := range m.backends {
		if err := b.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// schemeOf extracts the URI scheme from an endpoint string.
// "libp2p://..." → "libp2p"; "https://..." → "https"; "/p2p/..."
// (legacy multiaddr without scheme prefix) is special-cased to
// "libp2p" so the libp2p backend keeps working for users pasting
// raw multiaddrs.
func schemeOf(endpoint string) (string, error) {
	if endpoint == "" {
		return "", errors.New("empty endpoint")
	}
	if endpoint[0] == '/' {
		// Bare multiaddr, e.g. "/ip4/.../tcp/.../p2p/...". Route to
		// libp2p.
		return "libp2p", nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme == "" {
		return "", fmt.Errorf("endpoint %q has no scheme", endpoint)
	}
	return u.Scheme, nil
}
