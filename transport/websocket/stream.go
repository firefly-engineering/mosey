package websocket

import (
	"io"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/firefly-engineering/mosey/transport"
)

// stream wraps a [websocket.Conn] in mosey's [transport.Stream]
// semantics. Read pulls from the next binary message in order;
// Write emits a single binary frame.
//
// Concurrency: gorilla guarantees one concurrent reader + one
// concurrent writer per connection, which matches mosey's
// pumpStream shape (one goroutine reads, another writes). We don't
// take any locks of our own.
type stream struct {
	conn   *websocket.Conn
	remote string

	// curReader holds the io.Reader for the current binary message
	// while bytes from it remain. Refreshed when EOF is reached.
	curReader io.Reader

	closeOnce sync.Once
	closeErr  error
}

func (s *stream) Read(p []byte) (int, error) {
	for {
		if s.curReader == nil {
			mt, r, err := s.conn.NextReader()
			if err != nil {
				return 0, normalizeReadErr(err)
			}
			if mt != websocket.BinaryMessage {
				// Skip text / ping / pong frames silently; mosey
				// only puts bytes on the wire as binary.
				continue
			}
			s.curReader = r
		}
		n, err := s.curReader.Read(p)
		if err == io.EOF {
			s.curReader = nil
			// Don't surface a per-message EOF to the caller —
			// io.Copy and friends would stop on the first frame.
			// The stream's logical EOF comes from NextReader
			// returning a closed-stream error, handled above.
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (s *stream) Write(p []byte) (int, error) {
	if err := s.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (s *stream) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.conn.Close() })
	return s.closeErr
}

// CloseWrite isn't a thing on WebSocket — the Close frame is a
// full-connection close, not a half-close. mosey's existing
// callers (auth.Wrap, attach.Run, vterm) never call CloseWrite on
// the streams they use; returning ErrUnsupported keeps any future
// caller from quietly believing they sent a one-way FIN.
func (s *stream) CloseWrite() error { return transport.ErrUnsupported }

// RemoteID returns a string identifying the remote peer:
//
//   - On the server side: "ws-peer:<token>" derived from the
//     `Sec-WebSocket-Protocol: mosey-peer-<token>` value the
//     dialer offered. Stable across repeated connections from the
//     same backend, so [auth.Wrap] correlates the auth handshake
//     stream with subsequent application streams.
//
//   - On the client side: "ws://host" or "wss://host" — the URL
//     base that was dialed. The client doesn't need a stable
//     per-stream peer id (it knows its own identity via
//     [auth.Wrapped.LocalIdentity]); the URL is the most useful
//     thing to surface in logs.
func (s *stream) RemoteID() string { return s.remote }

// normalizeReadErr maps gorilla's "normal close" / "going away"
// codes to io.EOF so the caller sees a clean end-of-stream rather
// than a wrapped error. Any other failure is returned as-is.
func normalizeReadErr(err error) error {
	if websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseNoStatusReceived,
	) {
		return io.EOF
	}
	return err
}

var _ transport.Stream = (*stream)(nil)
