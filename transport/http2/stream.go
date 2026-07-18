package http2

import (
	"io"
	"net/http"
	"sync"

	"github.com/firefly-engineering/mosey/transport"
)

// clientStream is the dialer-side [transport.Stream]: writes flow
// through the request body (an [io.PipeWriter]); reads drain the
// response body. Closing the writer half-closes the request body
// (signals EOF to the server's r.Body.Read).
type clientStream struct {
	reader io.ReadCloser  // resp.Body
	writer io.WriteCloser // pipeW into req.Body
	remote string

	closeOnce sync.Once
	closeErr  error
}

func (s *clientStream) Read(p []byte) (int, error)  { return s.reader.Read(p) }
func (s *clientStream) Write(p []byte) (int, error) { return s.writer.Write(p) }

func (s *clientStream) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.writer.Close()
		_ = s.reader.Close()
	})
	return s.closeErr
}

// CloseWrite half-closes the request body without touching the
// response body — peer's r.Body.Read sees EOF, but we keep reading
// what they send us. Symmetric with libp2p's CloseWrite.
func (s *clientStream) CloseWrite() error { return s.writer.Close() }

// RemoteID returns the dialed host:port. HTTP/2 connections don't
// carry a richer peer identity in h2c mode; HTTPS variants can
// surface the TLS peer cert subject when that backend lands.
func (s *clientStream) RemoteID() string { return s.remote }

var _ transport.Stream = (*clientStream)(nil)

// serverStream is the listener-side [transport.Stream]: reads
// drain the request body, writes go through the response body
// (with explicit flushing so bytes leave the server promptly).
type serverStream struct {
	reader io.ReadCloser
	writer writeFlusher
	remote string

	closeOnce sync.Once
}

func (s *serverStream) Read(p []byte) (int, error)  { return s.reader.Read(p) }
func (s *serverStream) Write(p []byte) (int, error) { return s.writer.Write(p) }

func (s *serverStream) Close() error {
	s.closeOnce.Do(func() {
		// Closing the request body and signalling end-of-response
		// are HTTP/2's hand-back-to-the-server motions. We close
		// the reader; the response stream ends when the handler
		// returns.
		_ = s.reader.Close()
	})
	return nil
}

// serverStream deliberately does not implement [transport.HalfCloser]:
// returning from the handler is the only way to end the response body,
// so there is no half-close motion to expose. Callers signal "done
// writing" by closing the stream entirely.

// RemoteID returns the client's [http.Request.RemoteAddr] — typically
// the peer's IP:port. HTTPS / mTLS deployments can plumb in cert
// subject identification later.
func (s *serverStream) RemoteID() string { return s.remote }

var _ transport.Stream = (*serverStream)(nil)

// writeFlusher is the server-side writer: every Write is followed
// by a Flush so HTTP/2 stream chunks leave the response writer
// without server-side buffering. Without the flush, the std lib's
// chunked-response code can hold back bytes waiting for more data
// or for the handler to return — fatal for an interactive PTY
// where the user needs each keystroke's output as it happens.
type writeFlusher struct {
	w http.ResponseWriter
	f http.Flusher
}

func (wf writeFlusher) Write(p []byte) (int, error) {
	n, err := wf.w.Write(p)
	if n > 0 {
		wf.f.Flush()
	}
	return n, err
}
