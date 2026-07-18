package unix

import (
	"net"
	"sync"

	"github.com/firefly-engineering/mosey/transport"
)

// stream is one bidi byte channel: a *net.UnixConn with the
// length-prefixed protocol id already consumed. Implements
// [transport.Stream] including half-close via UnixConn.CloseWrite.
type stream struct {
	conn        *net.UnixConn
	remote      string
	correlation string

	closeOnce sync.Once
	closeErr  error
}

func (s *stream) Read(p []byte) (int, error)  { return s.conn.Read(p) }
func (s *stream) Write(p []byte) (int, error) { return s.conn.Write(p) }

func (s *stream) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.conn.Close() })
	return s.closeErr
}

// CloseWrite sends FIN; peer sees io.EOF on its next read but we
// can still read what they're sending us.
func (s *stream) CloseWrite() error { return s.conn.CloseWrite() }

// RemoteID returns a log tag for the remote peer:
//
//   - On the server side: "unix:uid=N:pid=M" from SO_PEERCRED (Linux)
//     or getpeereid + LOCAL_PEERPID (macOS) — the most useful tag an
//     AF_UNIX socket offers.
//   - On the client side: "unix://<path>" — the path that was dialed.
//
// Purely for logs — auth correlation reads [stream.CorrelationID].
func (s *stream) RemoteID() string { return s.remote }

// CorrelationID returns the per-caller correlation handle:
//
//   - On the server side: the "unix:uid=N:pid=M" peercreds string,
//     kernel-attested and stable across repeated connections from the
//     same caller process, so [auth.Wrap] links the auth handshake
//     stream to subsequent application streams.
//   - On the client side: "" — the dialer's own streams are never
//     looked up in a server-side identity map.
func (s *stream) CorrelationID() string { return s.correlation }

var _ transport.Stream = (*stream)(nil)
