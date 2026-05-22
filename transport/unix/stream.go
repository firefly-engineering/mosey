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
	conn   *net.UnixConn
	remote string

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

// RemoteID returns a string identifying the remote peer:
//
//   - On the server side: "unix:uid=N:pid=M" derived from SO_PEERCRED
//     (Linux) or getpeereid + LOCAL_PEERPID (macOS). Stable across
//     repeated connections from the same caller process, so the auth
//     layer can correlate the auth handshake stream with subsequent
//     application streams.
//
//   - On the client side: "unix://<path>" — the path that was dialed.
//     The client doesn't need a stable per-stream peer id (it knows
//     its own identity via [auth.Wrapped.LocalIdentity]), so the path
//     is the most useful thing to surface in logs.
func (s *stream) RemoteID() string { return s.remote }

var _ transport.Stream = (*stream)(nil)
