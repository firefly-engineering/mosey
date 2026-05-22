package streambuf

import (
	"errors"
	"sync"
)

// DefaultInputQueueBytes is the default total byte capacity of
// [InputQueue]. 64 KiB is large enough for a brief network blip's
// worth of typing — at human typing speed of 5 cps a user can fill
// at most ~300 bytes per minute, so this is over three hours of
// pent-up input. Bigger doesn't help, smaller risks dropping under
// paste loads.
const DefaultInputQueueBytes = 64 * 1024

// DropPolicy selects what an InputQueue does when an Enqueue would
// exceed the configured capacity.
type DropPolicy int

const (
	// DropOldest evicts the oldest queued chunks until the new write
	// fits. This is the default and the right answer when the bytes
	// being typed are interactive (terminal input) — the user's
	// latest keystrokes are more useful than something they typed
	// minutes ago.
	DropOldest DropPolicy = iota
	// DropNew refuses the write; Enqueue returns [ErrQueueFull] and
	// the queue is unchanged. Use this when callers want a clear
	// signal that data was dropped (e.g. structured input).
	DropNew
)

// ErrQueueFull is returned by [InputQueue.Enqueue] under DropNew when
// the queue can't fit the incoming chunk.
var ErrQueueFull = errors.New("streambuf: input queue is full and drop policy is DropNew")

// InputQueue is a bounded FIFO of byte chunks the stream-agent
// accumulates while the AttachAgent stream is disconnected. Chunks
// preserve message boundaries: the queue does not splice chunks
// together so the daemon receives bytes in the same shape they
// arrived from the PTY.
//
// Safe for concurrent use.
type InputQueue struct {
	mu       sync.Mutex
	chunks   [][]byte
	bytes    int
	capacity int
	policy   DropPolicy
}

// NewInputQueue constructs an InputQueue capped at capacity bytes
// across all queued chunks. capacity <= 0 means
// [DefaultInputQueueBytes]. policy controls eviction when the queue
// fills.
func NewInputQueue(capacity int, policy DropPolicy) *InputQueue {
	if capacity <= 0 {
		capacity = DefaultInputQueueBytes
	}
	return &InputQueue{capacity: capacity, policy: policy}
}

// Capacity returns the configured maximum number of bytes the queue
// will retain.
func (q *InputQueue) Capacity() int { return q.capacity }

// Len returns the number of queued chunks (not bytes).
func (q *InputQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.chunks)
}

// Bytes returns the number of bytes currently queued.
func (q *InputQueue) Bytes() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.bytes
}

// Enqueue appends chunk to the queue. The chunk is copied so the
// caller's buffer is free to be reused. Returns the number of bytes
// dropped to make room (0 in the common case) or [ErrQueueFull] under
// DropNew. A chunk larger than capacity itself is special-cased: it
// replaces the whole queue with its trailing capacity bytes (under
// DropOldest) or is rejected (under DropNew).
func (q *InputQueue) Enqueue(chunk []byte) (dropped int, err error) {
	if len(chunk) == 0 {
		return 0, nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(chunk) > q.capacity {
		if q.policy == DropNew {
			return 0, ErrQueueFull
		}
		// Replace queue with trailing capacity bytes of chunk.
		tail := chunk[len(chunk)-q.capacity:]
		droppedBefore := q.bytes
		q.chunks = q.chunks[:0]
		buf := make([]byte, len(tail))
		copy(buf, tail)
		q.chunks = append(q.chunks, buf)
		q.bytes = len(buf)
		return droppedBefore + (len(chunk) - q.capacity), nil
	}

	if q.bytes+len(chunk) <= q.capacity {
		buf := make([]byte, len(chunk))
		copy(buf, chunk)
		q.chunks = append(q.chunks, buf)
		q.bytes += len(buf)
		return 0, nil
	}

	if q.policy == DropNew {
		return 0, ErrQueueFull
	}
	for q.bytes+len(chunk) > q.capacity && len(q.chunks) > 0 {
		head := q.chunks[0]
		dropped += len(head)
		q.bytes -= len(head)
		q.chunks = q.chunks[1:]
	}
	buf := make([]byte, len(chunk))
	copy(buf, chunk)
	q.chunks = append(q.chunks, buf)
	q.bytes += len(buf)
	return dropped, nil
}

// Drain removes all queued chunks and returns them in FIFO order.
// The queue is empty on return. Callers typically Drain right after
// reconnect and re-send each chunk on the new stream.
func (q *InputQueue) Drain() [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.chunks
	q.chunks = nil
	q.bytes = 0
	return out
}

// Reset drops everything queued without returning it. Primarily for
// tests.
func (q *InputQueue) Reset() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.chunks = nil
	q.bytes = 0
}
