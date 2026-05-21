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

	"github.com/firefly-engineering/mosey/internal/transport"
)

// Scheme constants this backend claims under [transport.Multi].
// "http" is plaintext h2c; "https" is TLS-terminated HTTP/2.
const (
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
)

// Options configures a [Backend].
type Options struct {
	// ListenAddr is the host:port to bind. Zero / empty means
	// "client-only" — Endpoints() returns nil and inbound streams
	// are never received. Pass "0.0.0.0:0" for a random port on
	// all interfaces.
	ListenAddr string

	// TLSConfig, when non-nil, switches the listener to HTTPS:
	// the backend serves HTTP/2 over TLS using this config, and
	// Endpoints() returns "https://..." URLs. Callers are
	// responsible for populating Certificates (or GetCertificate)
	// before passing. Zero means plaintext h2c.
	TLSConfig *tls.Config

	// InsecureSkipVerify makes the client-side Dial path accept
	// any server certificate — useful for self-signed dev certs.
	// Affects only the Dial direction; the listener's behavior is
	// driven by TLSConfig.
	InsecureSkipVerify bool
}

// Backend implements [transport.Transport] over HTTP/2. Speaks
// h2c by default; switches to HTTPS when Options.TLSConfig is
// non-nil.
type Backend struct {
	server   *http.Server
	listener net.Listener
	addr     string // host:port the listener bound to
	useTLS   bool   // listener serves HTTPS rather than h2c

	mu       sync.Mutex
	handlers map[string]transport.Handler

	clientH2C   *http.Client // for http:// (cleartext) dials
	clientHTTPS *http.Client // for https:// dials; nil when not needed
}

// New constructs an HTTP/2 backend. When opts.ListenAddr is non-
// empty the backend immediately starts serving; clients-only
// callers may pass an empty ListenAddr and use the backend purely
// for Dial. When opts.TLSConfig is non-nil the listener serves
// HTTPS; otherwise plain h2c.
func New(ctx context.Context, opts Options) (*Backend, error) {
	b := &Backend{
		handlers:    map[string]transport.Handler{},
		useTLS:      opts.TLSConfig != nil,
		clientH2C:   buildH2CClient(),
		clientHTTPS: buildHTTPSClient(opts.InsecureSkipVerify),
	}

	if opts.ListenAddr != "" {
		lis, err := net.Listen("tcp", opts.ListenAddr)
		if err != nil {
			return nil, fmt.Errorf("http2: listen %q: %w", opts.ListenAddr, err)
		}
		b.listener = lis
		b.addr = lis.Addr().String()

		h2s := &http2.Server{}
		if opts.TLSConfig != nil {
			// HTTPS path: std-lib http.Server negotiates HTTP/2
			// via ALPN with the supplied TLS config.
			b.server = &http.Server{
				Handler:      http.HandlerFunc(b.serveHTTP),
				TLSConfig:    opts.TLSConfig.Clone(),
				ReadTimeout:  0,
				WriteTimeout: 0,
			}
			// Configure http2 on the server so we get the proper
			// h2 settings (priority, max-frame-size, etc.).
			if err := http2.ConfigureServer(b.server, h2s); err != nil {
				_ = lis.Close()
				return nil, fmt.Errorf("http2: configure server: %w", err)
			}
			go func() {
				_ = b.server.ServeTLS(lis, "", "") // cert/key already in TLSConfig
			}()
		} else {
			// h2c path: wrap the handler so plain-TCP requests
			// upgrade to HTTP/2 without TLS.
			b.server = &http.Server{
				Handler:      h2c.NewHandler(http.HandlerFunc(b.serveHTTP), h2s),
				ReadTimeout:  0,
				WriteTimeout: 0,
			}
			go func() {
				_ = b.server.Serve(lis)
			}()
		}
	}

	_ = ctx // reserved for shutdown plumbing; nothing uses it today
	return b, nil
}

// Schemes implements [transport.Transport]. The backend can Dial
// both http:// and https:// regardless of which scheme its
// listener serves (clients may need to reach a peer over either).
func (b *Backend) Schemes() []string { return []string{SchemeHTTP, SchemeHTTPS} }

// Endpoints implements [transport.Transport]. The advertised URL
// matches the listener's scheme — h2c → http://, TLS → https://.
func (b *Backend) Endpoints() []string {
	if b.addr == "" {
		return nil
	}
	if b.useTLS {
		return []string{"https://" + b.addr}
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
	if u.Scheme != SchemeHTTP && u.Scheme != SchemeHTTPS {
		return nil, fmt.Errorf("http2: unsupported scheme %q (want http or https)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("http2: endpoint %q missing host", endpoint)
	}
	target := *u
	target.Path = proto

	client := b.clientH2C
	if u.Scheme == SchemeHTTPS {
		client = b.clientHTTPS
	}

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

	type roundTripResult struct {
		resp *http.Response
		err  error
	}
	resultCh := make(chan roundTripResult, 1)
	go func() {
		resp, rerr := client.Do(req)
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
	if b.clientH2C != nil {
		b.clientH2C.CloseIdleConnections()
	}
	if b.clientHTTPS != nil {
		b.clientHTTPS.CloseIdleConnections()
	}
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

// buildHTTPSClient configures an HTTP client for the https:// dial
// path. http2.Transport with default DialTLSContext negotiates
// HTTP/2 via ALPN on a normal TLS connection — same behavior
// the std lib's http.Client gives for HTTPS, just pinned to h2.
//
// insecureSkipVerify accepts any server cert (intended for
// self-signed dev setups). Production callers should pass false
// and rely on the system trust store + the server's real cert.
func buildHTTPSClient(insecureSkipVerify bool) *http.Client {
	tr := &http2.Transport{}
	if insecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in
	}
	return &http.Client{Transport: tr}
}
