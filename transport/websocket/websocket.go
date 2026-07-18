// Package websocket is the WebSocket backend for mosey's
// [transport.Transport]. It claims the "ws" (cleartext) and "wss"
// (TLS) URI schemes and gives browser-based clients a path that
// works through any standard HTTP(S) infrastructure — reverse
// proxies, ingresses, CDNs, corporate TLS-terminators — using a
// protocol every browser speaks natively.
//
// Wire model: one WebSocket per stream. On Dial the client opens a
// fresh `ws://host/<protocol-id>` (or wss://) connection; the
// protocol id rides in the URL path the way it does in the HTTP/2
// backend. The server's HTTP handler dispatches by path to the
// registered [transport.Handler]. The WebSocket carries arbitrary
// bytes as binary frames; one [Stream.Write] = one binary frame.
//
// Identity correlation across the auth → application stream
// sequence is the only subtle part: each stream is a separate
// TCP+WS connection, so the natural RemoteAddr changes per dial
// (and is meaningless for browser clients behind NAT). Instead
// the dialer mints a random 128-bit per-process token at backend
// construction and offers it as a `mosey-peer-<hex>` value in the
// `Sec-WebSocket-Protocol` header on every dial; the server reads
// the same header on accept and uses the token as the stream's
// RemoteID. The subprotocol vehicle is browser-friendly (the only
// arbitrary client-controlled WebSocket handshake field exposed
// by the standard `new WebSocket(url, protocols)` API) and gives
// [auth.Wrap] the stable per-peer identity it needs.
package websocket

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/firefly-engineering/mosey/transport"
)

// Scheme constants this backend claims under [transport.Multi].
const (
	SchemeWS  = "ws"
	SchemeWSS = "wss"
)

// errPrefix tags errors emitted by this package.
const errPrefix = "transport/websocket: "

// peerTokenPrefix is the subprotocol-header prefix the dialer uses
// to smuggle a stable per-process peer id past the WebSocket
// handshake; the server uses what follows as the stream's
// RemoteID. Stable string — both sides agree on it; changing it
// would break correlation between an old client and a new server
// (or vice versa).
const peerTokenPrefix = "mosey-peer-"

// Options configures a [Backend].
type Options struct {
	// ListenAddr is the host:port to bind. Zero / empty means
	// "client-only" — Endpoints() returns nil and inbound
	// connections are never received. Pass "0.0.0.0:0" for a random
	// port on all interfaces.
	ListenAddr string

	// TLSConfig, when non-nil, switches the listener to wss://: the
	// backend serves WebSocket over TLS using this config, and
	// Endpoints() returns "wss://..." URLs. Callers populate
	// Certificates (or GetCertificate) before passing. Zero means
	// plain ws://.
	TLSConfig *tls.Config

	// InsecureSkipVerify makes the client-side Dial path accept any
	// server certificate for wss:// endpoints — useful for
	// self-signed dev certs. Mirrors the http2 backend's flag of
	// the same name.
	InsecureSkipVerify bool
}

// Backend implements [transport.Transport] over WebSockets.
type Backend struct {
	server   *http.Server
	listener net.Listener
	addr     string
	useTLS   bool

	mu       sync.Mutex
	handlers map[string]transport.Handler

	upgrader websocket.Upgrader
	dialer   *websocket.Dialer

	// peerToken is the stable RemoteID this backend's dialer
	// advertises on every outbound WebSocket. Generated once per
	// Backend so every Dial from the same backend correlates
	// server-side.
	peerToken string

	closeOnce sync.Once
}

// New constructs a WebSocket backend. When opts.ListenAddr is
// non-empty the backend immediately starts accepting; client-only
// callers pass an empty ListenAddr and use the backend purely for
// Dial.
func New(_ context.Context, opts Options) (*Backend, error) {
	token, err := mintPeerToken()
	if err != nil {
		return nil, fmt.Errorf(errPrefix+"mint peer token: %w", err)
	}
	b := &Backend{
		handlers:  map[string]transport.Handler{},
		useTLS:    opts.TLSConfig != nil,
		peerToken: token,
		upgrader: websocket.Upgrader{
			// Browser attaches will originate from arbitrary pages /
			// hosts; the auth handshake on top is what gates access,
			// not Origin. A locked-down Origin policy belongs to the
			// reverse proxy in production deployments.
			CheckOrigin:  func(*http.Request) bool { return true },
			Subprotocols: []string{
				// Empty placeholder; we override per-request by
				// echoing back whichever mosey-peer- subprotocol the
				// client offered (see selectSubprotocol).
			},
		},
		dialer: &websocket.Dialer{
			HandshakeTimeout: 0, // ctx-bounded via DialContext
		},
	}
	if opts.TLSConfig != nil {
		b.dialer.TLSClientConfig = opts.TLSConfig.Clone()
	}
	if opts.InsecureSkipVerify {
		if b.dialer.TLSClientConfig == nil {
			b.dialer.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		b.dialer.TLSClientConfig.InsecureSkipVerify = true
	}

	if opts.ListenAddr != "" {
		lis, err := net.Listen("tcp", opts.ListenAddr)
		if err != nil {
			return nil, fmt.Errorf(errPrefix+"listen %q: %w", opts.ListenAddr, err)
		}
		b.listener = lis
		b.addr = lis.Addr().String()
		b.server = &http.Server{
			Handler:      http.HandlerFunc(b.serveHTTP),
			ReadTimeout:  0,
			WriteTimeout: 0,
		}
		if opts.TLSConfig != nil {
			b.server.TLSConfig = opts.TLSConfig.Clone()
			go func() { _ = b.server.ServeTLS(lis, "", "") }()
		} else {
			go func() { _ = b.server.Serve(lis) }()
		}
	}
	return b, nil
}

// Schemes implements [transport.Transport]. The backend can Dial
// both ws:// and wss:// regardless of which scheme its listener
// serves.
func (b *Backend) Schemes() []string { return []string{SchemeWS, SchemeWSS} }

// Endpoints implements [transport.Transport]. The advertised URL
// matches the listener's scheme — plaintext → ws://, TLS → wss://.
func (b *Backend) Endpoints() []string {
	if b.addr == "" {
		return nil
	}
	if b.useTLS {
		return []string{"wss://" + b.addr}
	}
	return []string{"ws://" + b.addr}
}

// Handle implements [transport.Transport].
func (b *Backend) Handle(proto string, h transport.Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[proto] = h
}

// Unhandle implements [transport.Transport].
func (b *Backend) Unhandle(proto string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.handlers, proto)
}

// Dial implements [transport.Transport]. Opens a WebSocket against
// endpoint with URL path = protocol id, returns the connection as
// a [transport.Stream].
func (b *Backend) Dial(ctx context.Context, endpoint, proto string) (transport.Stream, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf(errPrefix+"parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != SchemeWS && u.Scheme != SchemeWSS {
		return nil, fmt.Errorf(errPrefix+"unsupported scheme %q (want ws or wss)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf(errPrefix+"endpoint %q missing host", endpoint)
	}
	target := *u
	target.Path = proto

	// Offer our per-backend peer token as a subprotocol; the server
	// uses it as the stream's RemoteID for auth correlation.
	dialer := *b.dialer
	dialer.Subprotocols = []string{peerTokenPrefix + b.peerToken}
	conn, resp, err := dialer.DialContext(ctx, target.String(), nil)
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf(errPrefix+"dial %s: %w (status %d)", target.String(), err, resp.StatusCode)
		}
		return nil, fmt.Errorf(errPrefix+"dial %s: %w", target.String(), err)
	}
	return &stream{conn: conn, remote: target.Scheme + "://" + target.Host}, nil
}

// Serve implements [transport.Transport]. The accept loop already
// runs from New (via http.Server.Serve in its own goroutine); Serve
// is a no-op so callers can use the same lifecycle pattern as other
// backends.
func (b *Backend) Serve() {}

// Close implements [transport.Transport].
func (b *Backend) Close() error {
	var err error
	b.closeOnce.Do(func() {
		if b.server != nil {
			err = b.server.Close()
		}
		if b.listener != nil {
			_ = b.listener.Close()
		}
	})
	return err
}

// serveHTTP upgrades an inbound HTTP request to WebSocket and
// dispatches to the matching handler. URL path is the protocol id;
// the subprotocol header carries the peer token (we echo it back
// per the WebSocket spec).
func (b *Backend) serveHTTP(w http.ResponseWriter, r *http.Request) {
	proto := r.URL.Path
	b.mu.Lock()
	h, ok := b.handlers[proto]
	b.mu.Unlock()
	if !ok {
		// Unknown protocol — 404 mirrors what HTTP infrastructure
		// already understands. Client backends translate this to
		// "protocol not supported".
		http.NotFound(w, r)
		return
	}
	peerToken := selectPeerToken(r.Header.Values("Sec-WebSocket-Protocol"))
	if peerToken == "" {
		// Refuse rather than admit a stream with an empty RemoteID —
		// which would alias with every other no-token connection in
		// the auth identity map. A correctly-built mosey dialer
		// always offers a token; absence is either a misconfigured
		// client or an outright probe.
		http.Error(w, "missing peer token", http.StatusBadRequest)
		return
	}
	// Echo the selected subprotocol back so the WebSocket handshake
	// completes per RFC 6455.
	upgrader := b.upgrader
	upgrader.Subprotocols = []string{peerTokenPrefix + peerToken}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrader has already written an HTTP error response.
		return
	}
	h(&stream{conn: conn, remote: r.RemoteAddr, correlation: "ws-peer:" + peerToken})
}

// selectPeerToken scans the Sec-WebSocket-Protocol values for the
// first one starting with peerTokenPrefix and returns the token
// suffix. Returns empty when no mosey-peer- subprotocol is offered.
// The header may carry either one comma-separated value or several
// header values — RFC 6455 allows both.
func selectPeerToken(offered []string) string {
	for _, raw := range offered {
		for _, candidate := range strings.Split(raw, ",") {
			candidate = strings.TrimSpace(candidate)
			if strings.HasPrefix(candidate, peerTokenPrefix) {
				return strings.TrimPrefix(candidate, peerTokenPrefix)
			}
		}
	}
	return ""
}

// mintPeerToken returns 32 hex chars of crypto-random data. Plenty
// of entropy for a per-process collision-resistant tag; short
// enough that the subprotocol header stays well under the typical
// HTTP header byte limits.
func mintPeerToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Compile-time check that Backend implements the interface. Saves
// a confusing diagnostic if the contract drifts.
var _ transport.Transport = (*Backend)(nil)
