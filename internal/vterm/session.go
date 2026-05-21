package vterm

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/creack/pty"

	"github.com/firefly-engineering/mosey/internal/auth"
	"github.com/firefly-engineering/mosey/internal/streambuf"
	"github.com/firefly-engineering/mosey/internal/transport"
)

// applyPTYSize updates the PTY winsize via TIOCSWINSZ. Caller
// should not hold session.mu.
func applyPTYSize(f *os.File, cols, rows uint32) error {
	return pty.Setsize(f, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

// readResumeSeq decodes the leading varint that a /mosey/pty-resume/
// client sends as its first bytes. Mirrors protowire's varint
// shape so the wire is stable.
func readResumeSeq(r io.Reader) (uint64, error) {
	var result uint64
	var shift uint
	one := []byte{0}
	for i := 0; i < 10; i++ { // varint max width for uint64
		n, err := r.Read(one)
		if n != 1 {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		b := one[0]
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, nil
		}
		shift += 7
	}
	return 0, fmt.Errorf("resume_seq varint overflow")
}

// encodeResumeSeq is the encoder counterpart of [readResumeSeq].
// Returns 1–10 bytes — proto-wire varint format.
func encodeResumeSeq(v uint64) []byte {
	var out [10]byte
	i := 0
	for v >= 0x80 {
		out[i] = byte(v) | 0x80
		v >>= 7
		i++
	}
	out[i] = byte(v)
	return out[:i+1]
}

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

	// remote is the auth-layer remote id captured at admit time.
	// Used by control.go to map an inbound /mosey/control/ stream
	// back to the right sessionClient when recording its
	// per-client geometry.
	remote string

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

	// cols / rows are this client's latest reported terminal
	// geometry. Zero means "no Resize seen from this client yet"
	// — the session ignores zero values when computing the PTY's
	// effective min size. Mutated under Session.mu.
	cols uint32
	rows uint32

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
		remote:   stream.RemoteID(),
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

// clientByRemoteIDLocked returns the most recently-added client
// whose RemoteID matches remote, or nil if none. Caller must hold
// s.mu. The "most recent" tiebreaker matters when one peer opens
// several streams — control messages apply to that peer's latest
// PTY attach.
func (s *Session) clientByRemoteIDLocked(remote string) *sessionClient {
	var latest *sessionClient
	for _, c := range s.clients {
		if c.remote != remote {
			continue
		}
		if latest == nil || c.id > latest.id {
			latest = c
		}
	}
	return latest
}

// applyResizeForRemote records the supplied cols/rows under the
// client owning remote, then recomputes the effective PTY size
// (min across every client with non-zero geometry). Returns the
// applied PTY size — zero/zero when no clients have reported a
// geometry yet.
func (s *Session) applyResizeForRemote(remote string, cols, rows uint32) (cols2, rows2 uint32, err error) {
	s.mu.Lock()
	c := s.clientByRemoteIDLocked(remote)
	if c == nil {
		s.mu.Unlock()
		return 0, 0, errResizeNoClient
	}
	c.cols = cols
	c.rows = rows
	pCols, pRows := s.minGeometryLocked()
	s.mu.Unlock()
	if pCols == 0 || pRows == 0 {
		return 0, 0, nil
	}
	if err := applyPTYSize(s.ptyf, pCols, pRows); err != nil {
		return 0, 0, fmt.Errorf("setsize: %w", err)
	}
	return pCols, pRows, nil
}

// minGeometryLocked computes the minimum cols × rows across every
// attached client that has reported a non-zero geometry. Caller
// holds s.mu. Returns 0/0 when no client has reported yet.
func (s *Session) minGeometryLocked() (cols, rows uint32) {
	var c, r uint32
	for _, cl := range s.clients {
		if cl.cols == 0 || cl.rows == 0 {
			continue
		}
		if c == 0 || cl.cols < c {
			c = cl.cols
		}
		if r == 0 || cl.rows < r {
			r = cl.rows
		}
	}
	return c, r
}

// recomputeGeometryAfterRemoveLocked recomputes the PTY size after
// a client leaves the session — if min just changed (because the
// constraining client left), the PTY may need to grow. Caller
// holds s.mu.
func (s *Session) recomputeGeometryAfterRemoveLocked() {
	cols, rows := s.minGeometryLocked()
	if cols == 0 || rows == 0 {
		return
	}
	// Apply asynchronously so we don't hold s.mu across a syscall.
	go func() {
		_ = applyPTYSize(s.ptyf, cols, rows)
	}()
}

// errResizeNoClient is the sentinel returned by
// applyResizeForRemote when the resize comes from a remote that
// has no matching PTY client — typically because the peer opened
// a control stream without a corresponding /mosey/pty/ session
// (a misbehaving client or a race during teardown).
var errResizeNoClient = fmt.Errorf("resize: no PTY client for remote")

// setMode swaps the session's active mode. Owner-only; the
// handler gates the check before calling this. The change applies
// to *future* attaches — existing clients keep their permissions
// so the running attach doesn't suddenly lose its terminal mid-
// command. Returns the prior mode for logging.
func (s *Session) setMode(m Mode) Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.mode
	s.mode = m
	return prev
}

// demoteRemote drops the write capability of the client matching
// remote. If that client was the PrimaryObserver writer, the seat
// becomes vacant. Returns true when a client was found + demoted,
// false when no client matched (rare race during teardown).
func (s *Session) demoteRemote(remote string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clientByRemoteIDLocked(remote)
	if c == nil {
		return false
	}
	c.canWrite = false
	if s.writerID == c.id {
		s.writerID = 0
	}
	return true
}

// listClients snapshots the registry. Caller gets a freshly
// allocated slice safe to consume without holding s.mu.
func (s *Session) listClients() []clientSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]clientSnapshot, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, clientSnapshot{
			ID:       c.id,
			Label:    c.identity.Label,
			CanWrite: c.canWrite,
			Cols:     c.cols,
			Rows:     c.rows,
		})
	}
	return out
}

// clientSnapshot is the read-only view of one registry entry. The
// wire form (api.ClientInfo) is derived from this in the control
// handler so the session package stays free of api types.
type clientSnapshot struct {
	ID       int64
	Label    string
	CanWrite bool
	Cols     uint32
	Rows     uint32
}

// promoteClient flips the target client's write permission on. In
// PrimaryObserver, the prior writer (if any) is demoted to keep
// the "single writer" invariant. Returns true on success, false
// when no client matched (already-disconnected target).
func (s *Session) promoteClient(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.clients[id]
	if !ok {
		return false
	}
	if s.mode == ModePrimaryObserver {
		if prev, ok := s.clients[s.writerID]; ok && prev != target {
			prev.canWrite = false
		}
		s.writerID = id
	}
	target.canWrite = true
	return true
}

// kickClient evicts a client by id. The target's stream-close path
// fires through its done channel; its handlePTY goroutines exit
// and the registry entry is removed asynchronously. Returns true
// on success, false when no client matched.
func (s *Session) kickClient(id int64) bool {
	s.mu.Lock()
	c, ok := s.clients[id]
	if ok {
		c.kick()
	}
	s.mu.Unlock()
	return ok
}

// removeClient drops a client from the registry and fires its
// kick if it hadn't already. Safe to call from the handler's
// defer regardless of who initiated the disconnect. Triggers a
// PTY geometry recompute — the leaving client may have been the
// constraining party for min(cols) / min(rows).
func (s *Session) removeClient(id int64) {
	s.mu.Lock()
	if c, ok := s.clients[id]; ok {
		c.kick()
		delete(s.clients, id)
	}
	if s.writerID == id {
		s.writerID = 0
	}
	s.recomputeGeometryAfterRemoveLocked()
	s.mu.Unlock()
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
