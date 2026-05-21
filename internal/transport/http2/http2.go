// Package http2 is the HTTP/2 backend for ship's [transport.Transport].
// It speaks "http://" (h2c — HTTP/2 cleartext) today; HTTPS support
// follows once TLS configuration plumbs through.
//
// Wire model: every ship "stream" maps to one HTTP/2 stream. URL path
// carries the ship protocol id (`/ship/pty/1.0.0` etc.); request body
// is client→server bytes; response body is server→client bytes.
// HTTP/2 multiplexes any number of streams over one TCP connection,
// so the per-connection cost of opening additional streams is the
// same here as on the libp2p side.
//
// Asymmetry note: HTTP/2 is dialer→listener. The Transport interface
// itself is symmetric (both sides can Handle + Dial), but on this
// backend a process that never calls New(..., Options{Listen: "..."})
// has no Endpoints() to share — client-only. ship's `attach` is
// client-only by design, so that works out.
package http2

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/firefly-engineering/ship/internal/transport"
)

// SchemeHTTP is the URI scheme this backend claims for h2c
// connections. HTTPS will register as a separate scheme when the
// TLS path lands.
const SchemeHTTP = "http"

// Options configures a [Backend].
type Options struct {
	// ListenAddr is the host:port to bind. Zero / empty means
	// "client-only" — Endpoints() returns nil and inbound streams
	// are never received. Pass "0.0.0.0:0" for a random port on
	// all interfaces.
	ListenAddr string
}

// Backend implements [transport.Transport] over HTTP/2 (h2c).
type Backend struct {
	server   *http.Server
	listener net.Listener
	addr     string // host:port the listener bound to

	mu       sync.Mutex
	handlers map[string]transport.Handler

	client *http.Client
}

// New constructs an HTTP/2 backend. When opts.ListenAddr is non-
// empty the backend immediately starts serving; clients-only
// callers may pass an empty ListenAddr and use the backend purely
// for Dial.
func New(ctx context.Context, opts Options) (*Backend, error) {
	b := &Backend{
		handlers: map[string]transport.Handler{},
		client:   buildH2CClient(),
	}

	if opts.ListenAddr != "" {
		lis, err := net.Listen("tcp", opts.ListenAddr)
		if err != nil {
			return nil, fmt.Errorf("http2: listen %q: %w", opts.ListenAddr, err)
		}
		b.listener = lis
		b.addr = lis.Addr().String()

		h2s := &http2.Server{}
		b.server = &http.Server{
			Handler: h2c.NewHandler(http.HandlerFunc(b.serveHTTP), h2s),
			// HTTP/2 streams can stay open indefinitely (long-lived
			// PTY bridge), so don't time them out at the server
			// level. The transport.Stream lifecycle handles teardown.
			ReadTimeout:  0,
			WriteTimeout: 0,
		}
		go func() {
			_ = b.server.Serve(lis)
		}()
	}

	_ = ctx // reserved for shutdown plumbing; nothing uses it today
	return b, nil
}

// Schemes implements [transport.Transport].
func (b *Backend) Schemes() []string { return []string{SchemeHTTP} }

// Endpoints implements [transport.Transport]. Returns one URL per
// bound interface — for the typical 0.0.0.0 bind, that's just the
// resolved listener address.
func (b *Backend) Endpoints() []string {
	if b.addr == "" {
		return nil
	}
	return []string{"http://" + b.addr}
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

// Dial implements [transport.Transport]. Opens a streaming HTTP/2
// POST against endpoint with URL path = protocol id. Returns a
// [transport.Stream] whose writes flow as the request body and
// whose reads drain the response body.
func (b *Backend) Dial(ctx context.Context, endpoint, proto string) (transport.Stream, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("http2: parse endpoint %q: %w", endpoint, err)
	}
	if u.Scheme != SchemeHTTP {
		return nil, fmt.Errorf("http2: unsupported scheme %q (want http)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("http2: endpoint %q missing host", endpoint)
	}
	target := *u
	target.Path = proto

	pipeR, pipeW := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), pipeR)
	if err != nil {
		_ = pipeW.Close()
		_ = pipeR.Close()
		return nil, fmt.Errorf("http2: build request: %w", err)
	}
	// Without ContentLength = -1, the std lib HTTP client tries to
	// fully consume the request body before delivering the response
	// — bidi streams die. -1 tells it the body is open-ended.
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/octet-stream")

	// Use an explicit channel to capture the response; doing so in
	// a goroutine lets the caller start writing to pipeW (and
	// thereby the request body) before the response headers arrive.
	type roundTripResult struct {
		resp *http.Response
		err  error
	}
	resultCh := make(chan roundTripResult, 1)
	go func() {
		resp, rerr := b.client.Do(req)
		resultCh <- roundTripResult{resp: resp, err: rerr}
	}()

	// Wait for the response (or ctx cancel). The server flushes its
	// headers as soon as the handler starts so we get past this
	// quickly when there's a handler registered.
	var resp *http.Response
	select {
	case res := <-resultCh:
		if res.err != nil {
			_ = pipeW.Close()
			return nil, fmt.Errorf("http2: dial: %w", res.err)
		}
		resp = res.resp
	case <-ctx.Done():
		_ = pipeW.Close()
		return nil, ctx.Err()
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pipeW.Close()
		return nil, fmt.Errorf("http2: dial %s %s: status %d", proto, endpoint, resp.StatusCode)
	}

	return &clientStream{
		reader: resp.Body,
		writer: pipeW,
		remote: target.Host,
	}, nil
}

// Close implements [transport.Transport].
func (b *Backend) Close() error {
	if b.server != nil {
		_ = b.server.Close()
	}
	if b.listener != nil {
		_ = b.listener.Close()
	}
	b.client.CloseIdleConnections()
	return nil
}

// serveHTTP dispatches one inbound HTTP/2 stream to the matching
// ship handler. The handler receives a [transport.Stream]; closing
// it ends the HTTP/2 stream cleanly.
func (b *Backend) serveHTTP(w http.ResponseWriter, r *http.Request) {
	proto := r.URL.Path
	b.mu.Lock()
	h, ok := b.handlers[proto]
	b.mu.Unlock()
	if !ok {
		http.Error(w, "protocol not supported", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "server does not support streaming", http.StatusInternalServerError)
		return
	}

	// Commit headers immediately so the client's Dial unblocks. The
	// handler then has a fully bidi stream: read from r.Body, write
	// to w (flushing after each write so bytes flow without
	// buffering).
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	stream := &serverStream{
		reader: r.Body,
		writer: writeFlusher{w: w, f: flusher},
		remote: r.RemoteAddr,
	}
	h(stream)
}

// buildH2CClient configures an HTTP client that speaks h2c (HTTP/2
// without TLS). The default http.Client only does HTTP/2 over TLS;
// for cleartext we override Transport with http2.Transport +
// AllowHTTP + a DialTLSContext that returns a plain TCP conn —
// http2.Transport then runs the HTTP/2 handshake directly over the
// TCP socket.
func buildH2CClient() *http.Client {
	return &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
	}
}
