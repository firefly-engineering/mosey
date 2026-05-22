// Package unix is the unix-domain-socket backend for mosey's
// [transport.Transport]. It claims the "unix" URI scheme and gives
// same-host peers an attach path that doesn't need a network port,
// TLS, or libp2p bootstrap chatter.
//
// Wire model: one socket per stream. On Dial the client opens a
// fresh [net.UnixConn] to the listener's path and writes a varint-
// length-prefixed protocol id; the server reads the prefix, looks
// up the registered handler, and treats the rest of the socket as
// the bidi byte stream. Per-stream sockets keep the implementation
// minimal — no multiplexer — at the cost of one socket(2) +
// connect(2) per stream open. Both are cheap on unix sockets, and
// mosey opens streams sparingly (auth + pty + control per attach).
//
// Identity correlation across the auth → application stream
// sequence is the only subtle part: each stream is a separate
// socket, so RemoteID can't fall out of the connection address.
// Instead the server pulls peer credentials (uid + pid) on accept
// — same caller process produces a stable RemoteID across both
// streams, which is what [auth.Wrap] keys on to wire up
// per-connection identity.
package unix

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sync"

	"github.com/firefly-engineering/mosey/transport"
)

// Scheme is the URI scheme this backend claims under
// [transport.Multi].
const Scheme = "unix"

// errPrefix tags errors emitted by this package.
const errPrefix = "transport/unix: "

// maxProtoLen caps the protocol-id prefix the server is willing to
// read on accept. The longest mosey protocol id today is
// `/mosey/pty-resume/1.0.0` (23 bytes); 256 bytes is a generous
// ceiling that still rules out a malicious peer feeding a
// gigabyte of varint before the handler boots.
const maxProtoLen = 256

// Options configures a [Backend].
type Options struct {
	// ListenAddr is the filesystem path to bind. Zero / empty means
	// "client-only" — Endpoints() returns nil and inbound streams
	// are never received. The path is created on bind and unlinked
	// on Close.
	ListenAddr string
}

// Backend implements [transport.Transport] over unix domain sockets.
type Backend struct {
	listener *net.UnixListener
	addr     string // filesystem path bound by the listener

	mu       sync.Mutex
	handlers map[string]transport.Handler

	closeOnce sync.Once
	closeCh   chan struct{}
}

// New constructs a unix backend. When opts.ListenAddr is non-empty
// the backend immediately starts accepting; client-only callers
// pass an empty ListenAddr and use the backend purely for Dial.
func New(_ context.Context, opts Options) (*Backend, error) {
	b := &Backend{
		handlers: map[string]transport.Handler{},
		closeCh:  make(chan struct{}),
	}
	if opts.ListenAddr == "" {
		return b, nil
	}
	// A stale socket from a prior crashed launcher would make Listen
	// fail with EADDRINUSE; the standard unix-socket pattern is to
	// remove first and let the listener (re)create. Connecting to a
	// removed-but-still-open socket isn't possible — the kernel
	// scopes by inode, and the unlinked path can't be looked up by
	// new dialers.
	_ = os.Remove(opts.ListenAddr)
	lis, err := net.ListenUnix(Scheme, &net.UnixAddr{Name: opts.ListenAddr, Net: Scheme})
	if err != nil {
		return nil, fmt.Errorf(errPrefix+"listen %q: %w", opts.ListenAddr, err)
	}
	b.listener = lis
	b.addr = opts.ListenAddr
	go b.acceptLoop()
	return b, nil
}

// Schemes implements [transport.Transport].
func (b *Backend) Schemes() []string { return []string{Scheme} }

// Endpoints implements [transport.Transport]. Returns the
// canonical `unix://<path>` form so [transport.Multi]'s scheme
// router can dispatch outbound Dials back to this backend.
func (b *Backend) Endpoints() []string {
	if b.addr == "" {
		return nil
	}
	return []string{"unix://" + b.addr}
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

// Dial implements [transport.Transport]. Opens a fresh unix socket
// to endpoint's path, writes the protocol-id prefix, and returns
// the rest of the socket as a [transport.Stream].
func (b *Backend) Dial(ctx context.Context, endpoint, proto string) (transport.Stream, error) {
	path, err := parseUnixEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	if proto == "" {
		return nil, errors.New(errPrefix + "protocol id required")
	}
	if len(proto) > maxProtoLen {
		return nil, fmt.Errorf(errPrefix+"protocol id length %d exceeds %d", len(proto), maxProtoLen)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, Scheme, path)
	if err != nil {
		return nil, fmt.Errorf(errPrefix+"dial %q: %w", path, err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf(errPrefix+"dial %q: unexpected conn type %T", path, conn)
	}
	if err := writeProto(uc, proto); err != nil {
		_ = uc.Close()
		return nil, fmt.Errorf(errPrefix+"write proto: %w", err)
	}
	return &stream{conn: uc, remote: "unix://" + path}, nil
}

// Serve implements [transport.Transport]. Unix's accept loop is
// already running from New (see acceptLoop); Serve is a no-op so
// callers can use the same lifecycle pattern as other backends.
func (b *Backend) Serve() {}

// Close implements [transport.Transport]. Closes the listener and
// removes the bound path. Already-open streams keep working until
// the caller closes them.
func (b *Backend) Close() error {
	var err error
	b.closeOnce.Do(func() {
		close(b.closeCh)
		if b.listener != nil {
			err = b.listener.Close()
			_ = os.Remove(b.addr)
		}
	})
	return err
}

// acceptLoop accepts incoming connections and dispatches each to
// the handler matching its protocol-id prefix.
func (b *Backend) acceptLoop() {
	for {
		conn, err := b.listener.AcceptUnix()
		if err != nil {
			select {
			case <-b.closeCh:
				return
			default:
			}
			// Listener still live but accept failed — most likely a
			// transient resource issue. Returning would silently stop
			// serving; logging would require a slog dep this package
			// doesn't carry. Bail out and let the caller notice via a
			// subsequent failed Dial.
			return
		}
		go b.handleConn(conn)
	}
}

// handleConn reads the protocol prefix and dispatches to the
// matching handler, or closes if no handler is registered.
func (b *Backend) handleConn(conn *net.UnixConn) {
	proto, err := readProto(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	b.mu.Lock()
	h, ok := b.handlers[proto]
	b.mu.Unlock()
	if !ok {
		// Unknown protocol — closing without a response is
		// intentional, matching libp2p's "protocol not supported"
		// posture (don't help probers distinguish what's registered).
		_ = conn.Close()
		return
	}
	remote, err := peerCredsRemoteID(conn)
	if err != nil {
		// Couldn't read peer creds — refuse the stream rather than
		// hand the handler a connection with an empty RemoteID, which
		// would alias with every other no-creds connection in the
		// auth identity map.
		_ = conn.Close()
		return
	}
	h(&stream{conn: conn, remote: remote})
}

// parseUnixEndpoint accepts either `unix:///path/to/sock` or a bare
// filesystem path (when a caller already knows the scheme). The
// `unix:` form mirrors how the listener advertises itself in
// Endpoints, so [transport.Multi]'s scheme-based router roundtrips.
func parseUnixEndpoint(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err == nil && u.Scheme == Scheme {
		if u.Path == "" {
			return "", fmt.Errorf(errPrefix+"endpoint %q has no path", endpoint)
		}
		return u.Path, nil
	}
	// Bare path fallback: useful from tests + internal callers that
	// already know they're hitting unix.
	if endpoint == "" {
		return "", errors.New(errPrefix + "empty endpoint")
	}
	return endpoint, nil
}

// writeProto frames the protocol id as varint(len) + bytes onto w.
func writeProto(w io.Writer, proto string) error {
	var hdr [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(hdr[:], uint64(len(proto)))
	if _, err := w.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := w.Write([]byte(proto))
	return err
}

// readProto reads the varint length prefix and the protocol id
// bytes. Refuses lengths above maxProtoLen so a misbehaving peer
// can't make the server allocate unbounded memory.
func readProto(r io.Reader) (string, error) {
	br := byteReader{r: r}
	length, err := binary.ReadUvarint(br)
	if err != nil {
		return "", fmt.Errorf("read varint: %w", err)
	}
	if length == 0 {
		return "", errors.New("empty protocol id")
	}
	if length > maxProtoLen {
		return "", fmt.Errorf("protocol id length %d exceeds %d", length, maxProtoLen)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read protocol id: %w", err)
	}
	return string(buf), nil
}

// byteReader adapts an io.Reader to io.ByteReader for
// binary.ReadUvarint. One-byte reads are fine here — the varint is
// at most 10 bytes.
type byteReader struct{ r io.Reader }

func (b byteReader) ReadByte() (byte, error) {
	var p [1]byte
	if _, err := io.ReadFull(b.r, p[:]); err != nil {
		return 0, err
	}
	return p[0], nil
}
