package streambuf

import (
	"errors"
	"sync"
)

// DefaultOutputRingBytes is the default per-agent ring capacity:
// 256 KiB — comfortably above a screenful of `top`, ~12 MiB across
// 50 attached agents.
const DefaultOutputRingBytes = 256 * 1024

// ErrSeqBehindRing is returned by [OutputRing.From] when the caller's
// last-seen sequence is so old it has already fallen out of the
// retained window. Callers should treat this the same as a fresh
// attach: skip the replay attempt and accept they missed some output.
var ErrSeqBehindRing = errors.New("streambuf: requested sequence is older than the ring's retained window")

// OutputRing buffers agent → pane PTY bytes for replay on reattach.
// Bytes carry a monotonic Seq counter (1-based; 0 means "never been
// written"). The most recent N bytes are retained, dropping the
// oldest first when the buffer fills.
//
// Safe for concurrent use. Reads under [OutputRing.From] return a
// freshly allocated slice the caller owns.
type OutputRing struct {
	mu       sync.Mutex
	data     []byte
	capacity int
	// firstSeq is the sequence of the first byte currently in data.
	// 1-based to keep "0 == zero value == nothing yet" unambiguous.
	firstSeq uint64
}

// NewOutputRing constructs an OutputRing retaining up to capacity
// bytes. capacity <= 0 means [DefaultOutputRingBytes].
func NewOutputRing(capacity int) *OutputRing {
	if capacity <= 0 {
		capacity = DefaultOutputRingBytes
	}
	return &OutputRing{
		data:     make([]byte, 0, capacity),
		capacity: capacity,
		firstSeq: 1,
	}
}

// Capacity returns the configured maximum number of bytes the ring
// retains.
func (r *OutputRing) Capacity() int { return r.capacity }

// Write appends p, evicting oldest bytes if needed. Never partial,
// never an error: it returns firstSeq — the sequence of the *first*
// byte of p as written into the ring — and n == len(p). (Callers
// needing the sequence of the last byte add len(p)-1.)
//
// The (firstSeq, n) return is deliberately not [io.Writer]-shaped:
// the sequence number is load-bearing for replay, so OutputRing is
// not an io.Writer and cannot be used as an [io.Copy] destination.
func (r *OutputRing) Write(p []byte) (firstSeq uint64, n int) {
	if len(p) == 0 {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.nextSeqLocked(), 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	firstSeq = r.nextSeqLocked()

	if len(p) >= r.capacity {
		// Bigger than the whole ring — keep only the trailing
		// capacity bytes.
		r.data = append(r.data[:0], p[len(p)-r.capacity:]...)
		r.firstSeq = firstSeq + uint64(len(p)-r.capacity)
		return firstSeq, len(p)
	}

	overflow := len(r.data) + len(p) - r.capacity
	if overflow > 0 {
		copy(r.data, r.data[overflow:])
		r.data = r.data[:len(r.data)-overflow]
		r.firstSeq += uint64(overflow)
	}
	r.data = append(r.data, p...)
	return firstSeq, len(p)
}

// State snapshots the ring's boundary cursors. Useful for unit tests
// and for AgentReady payloads.
type State struct {
	// FirstSeq is the sequence of the oldest byte still retained. 0
	// means the ring has never been written to.
	FirstSeq uint64
	// NextSeq is the sequence the *next* Write will start at. Also
	// equals FirstSeq + len(retained bytes).
	NextSeq uint64
	// Bytes is the number of bytes currently retained.
	Bytes int
}

// State returns the current ring boundary cursors.
func (r *OutputRing) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.data) == 0 {
		return State{FirstSeq: r.firstSeq, NextSeq: r.firstSeq, Bytes: 0}
	}
	return State{
		FirstSeq: r.firstSeq,
		NextSeq:  r.firstSeq + uint64(len(r.data)),
		Bytes:    len(r.data),
	}
}

// From returns the bytes whose first-byte sequence is `since` or
// later. `since == 0` means "fresh attach" — the caller wants
// whatever the ring has without claiming any prior position; the
// full retained window is returned without an error.
//
// For nonzero `since`:
//   - since < firstSeq (caller missed some evicted output): the
//     retained window is still returned but err = [ErrSeqBehindRing]
//     so the caller can decide whether the partial replay is good
//     enough.
//   - firstSeq <= since < nextSeq: the suffix starting at `since` is
//     returned.
//   - since >= nextSeq: caller is already current; nil is returned.
//
// The returned slice is freshly allocated; the caller owns it.
func (r *OutputRing) From(since uint64) (data []byte, nextSeq uint64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.data) == 0 {
		return nil, r.firstSeq, nil
	}
	ringEnd := r.firstSeq + uint64(len(r.data))
	if since >= ringEnd {
		return nil, ringEnd, nil
	}
	var start int
	var dropped bool
	switch {
	case since == 0:
		// Fresh attach — give everything, no error.
		start = 0
	case since < r.firstSeq:
		start = 0
		dropped = true
	default:
		start = int(since - r.firstSeq)
	}
	out := make([]byte, len(r.data)-start)
	copy(out, r.data[start:])
	if dropped {
		return out, ringEnd, ErrSeqBehindRing
	}
	return out, ringEnd, nil
}

// Reset drops the retained bytes and rewinds the sequence counter
// (so the next Write starts at firstSeq == 1). Primarily for tests.
func (r *OutputRing) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data = r.data[:0]
	r.firstSeq = 1
}

// nextSeqLocked returns the sequence the next byte will live at.
// Caller must hold r.mu.
func (r *OutputRing) nextSeqLocked() uint64 {
	return r.firstSeq + uint64(len(r.data))
}
