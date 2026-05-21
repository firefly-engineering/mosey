package vterm

import (
	"io"
	"sync"
	"sync/atomic"

	"github.com/firefly-engineering/ship/internal/auth"
	"github.com/firefly-engineering/ship/internal/streambuf"
	"github.com/firefly-engineering/ship/internal/transport"
)

// outputRingCapacity bounds the PTY-output replay buffer. ~256 KiB
// is comfortably above a screenful of `top` and lets a freshly
// attaching client see the last few seconds of output without
// needing to wait for a redraw.
const outputRingCapacity = 256 * 1024

// clientBufferChunks is the per-client output channel depth. 256
// pending byte-chunks ≈ ~64 KiB of in-flight output (typical chunk
// size is 256–512 bytes from a 4096 PTY read). Slow clients that
// blow through this get their pending bytes dropped on the floor;
// they can resume from the [streambuf.OutputRing] when (if) they
// reconnect.
const clientBufferChunks = 256

// sessionClient is one currently-attached client. The Session
// owns the pty + the registry; each client owns a stream + an
// output goroutine + an input goroutine, all torn down when
// done is closed.
type sessionClient struct {
	id       int64
	stream   transport.Stream
	identity auth.Identity

	// outCh is the per-client live output channel. The session's
	// pty-pump fan-outs every byte-chunk onto every client's outCh
	// using non-blocking send; full → dropped (slow client).
	outCh chan []byte

	// done fires when the session evicts this client (mode-driven
	// kick, session shutdown). Closes after the registry drops
	// the entry so listeners only see it once.
	done chan struct{}

	// canWrite is the effective write permission. May be narrower
	// than identity.CanWrite() — PrimaryObserver mode demotes
	// secondary attachers even when their identity grants Write.
	// Mutated under Session.mu.
	canWrite bool

	// kickOnce guards close(done) so eviction stays idempotent.
	kickOnce sync.Once

	// dropped is incremented every time the pty pump can't push a
	// chunk because outCh is full. Exposed for tests / observability.
	dropped atomic.Int64
}

// kick evicts this client. Idempotent — calling kick on an
// already-evicted client is a no-op.
func (c *sessionClient) kick() {
	c.kickOnce.Do(func() {
		close(c.done)
	})
}

// addClient is the mode-aware admission gate. Returns the new
// client (registered in s.clients) or nil if the current mode
// refuses the attach. Holds s.mu for the duration; callers must
// not hold it.
func (s *Session) addClient(stream transport.Stream) *sessionClient {
	identity := auth.IdentityOf(stream)

	s.mu.Lock()
	defer s.mu.Unlock()

	canWrite := identity.CanWrite()

	switch s.mode {
	case ModeExclusive:
		if len(s.clients) > 0 {
			return nil
		}

	case ModeSupersede:
		for _, c := range s.clients {
			c.kick()
		}
		// The kicked clients tear themselves down via handlePTY's
		// defer; the registry entries get removed asynchronously.
		// Continue and add the new client.

	case ModePrimaryObserver:
		// Writer seat is taken iff s.writerID points at a live
		// client. If vacant and the new client has Write cap,
		// promote it.
		if _, exists := s.clients[s.writerID]; !exists {
			s.writerID = 0
		}
		if canWrite && s.writerID == 0 {
			// Take the seat. canWrite stays true.
		} else {
			canWrite = false
		}

	case ModeMultiWrite:
		// Anyone with Write cap can type; bytes interleave.
		// canWrite already mirrors identity.

	default:
		return nil
	}

	s.nextID++
	c := &sessionClient{
		id:       s.nextID,
		stream:   stream,
		identity: identity,
		outCh:    make(chan []byte, clientBufferChunks),
		done:     make(chan struct{}),
		canWrite: canWrite,
	}
	s.clients[c.id] = c
	if s.mode == ModePrimaryObserver && canWrite {
		s.writerID = c.id
	}
	return c
}

// removeClient drops a client from the registry and fires its
// kick if it hadn't already. Safe to call from the handler's
// defer regardless of who initiated the disconnect.
func (s *Session) removeClient(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clients[id]; ok {
		c.kick()
		delete(s.clients, id)
	}
	if s.writerID == id {
		s.writerID = 0
	}
}

// broadcast fans a PTY byte-chunk out to every live client. Lock
// is taken so we can iterate the map; send to per-client channel
// is non-blocking — slow clients drop chunks rather than stall
// the PTY pump (and thus the child process).
func (s *Session) broadcast(chunk []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.clients {
		select {
		case c.outCh <- chunk:
		default:
			c.dropped.Add(1)
		}
	}
}

// shutdown kicks every client and clears the registry. Called
// when the wrapped child process exits — clients see EOF and
// exit cleanly.
func (s *Session) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.clients {
		c.kick()
	}
	s.clients = map[int64]*sessionClient{}
	s.writerID = 0
}

// pumpOutput reads PTY output forever, writes it to the
// OutputRing (for replay-on-reconnect), and broadcasts to every
// active client. Exits when the PTY hits EOF (child closed) or
// errors.
func (s *Session) pumpOutput() {
	buf := make([]byte, 4096)
	for {
		n, err := s.ptyf.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			s.output.Write(chunk)
			s.broadcast(chunk)
		}
		if err != nil {
			if err != io.EOF {
				s.logger.Debug("pty read ended", "err", err)
			}
			return
		}
	}
}

// newOutputRing is a thin wrapper so tests can swap in a smaller
// ring for replay-edge cases.
func newOutputRing() *streambuf.OutputRing {
	return streambuf.NewOutputRing(outputRingCapacity)
}
