package streambuf_test

import (
	"errors"
	"runtime"
	"sync"
	"testing"

	"github.com/firefly-engineering/ship/internal/streambuf"
)

func TestInputQueue_DefaultCapacity(t *testing.T) {
	t.Parallel()
	q := streambuf.NewInputQueue(0, streambuf.DropOldest)
	if got, want := q.Capacity(), streambuf.DefaultInputQueueBytes; got != want {
		t.Fatalf("Capacity = %d, want %d", got, want)
	}
}

func TestInputQueue_EnqueueDrainPreservesChunkBoundaries(t *testing.T) {
	t.Parallel()
	q := streambuf.NewInputQueue(64, streambuf.DropOldest)
	for _, c := range []string{"alpha", "beta", "gamma"} {
		if dropped, err := q.Enqueue([]byte(c)); dropped != 0 || err != nil {
			t.Fatalf("Enqueue(%q): dropped=%d err=%v", c, dropped, err)
		}
	}
	chunks := q.Drain()
	if got := []string{string(chunks[0]), string(chunks[1]), string(chunks[2])}; got[0] != "alpha" || got[1] != "beta" || got[2] != "gamma" {
		t.Fatalf("Drain = %v, want [alpha beta gamma]", got)
	}
	if q.Len() != 0 || q.Bytes() != 0 {
		t.Fatalf("post-Drain: Len=%d Bytes=%d, want 0,0", q.Len(), q.Bytes())
	}
}

func TestInputQueue_EnqueueCopiesCallerBuffer(t *testing.T) {
	t.Parallel()
	q := streambuf.NewInputQueue(64, streambuf.DropOldest)
	caller := []byte("hello")
	if _, err := q.Enqueue(caller); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// Mutate the caller's buffer — the queued copy must not change.
	caller[0] = 'X'
	chunks := q.Drain()
	if string(chunks[0]) != "hello" {
		t.Fatalf("queued chunk = %q, want hello (caller mutation must not leak)", chunks[0])
	}
}

func TestInputQueue_DropOldestOnOverflow(t *testing.T) {
	t.Parallel()
	q := streambuf.NewInputQueue(8, streambuf.DropOldest)
	_, _ = q.Enqueue([]byte("aaaa")) // 4 bytes
	_, _ = q.Enqueue([]byte("bbbb")) // 8 total
	dropped, err := q.Enqueue([]byte("cc"))
	if err != nil {
		t.Fatalf("Enqueue overflow: %v", err)
	}
	if dropped != 4 {
		t.Fatalf("dropped = %d, want 4 (aaaa evicted)", dropped)
	}
	chunks := q.Drain()
	if len(chunks) != 2 || string(chunks[0]) != "bbbb" || string(chunks[1]) != "cc" {
		t.Fatalf("Drain = %v, want [bbbb cc]", chunks)
	}
}

func TestInputQueue_DropNewReturnsErrQueueFull(t *testing.T) {
	t.Parallel()
	q := streambuf.NewInputQueue(4, streambuf.DropNew)
	if _, err := q.Enqueue([]byte("aaaa")); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	dropped, err := q.Enqueue([]byte("b"))
	if !errors.Is(err, streambuf.ErrQueueFull) {
		t.Fatalf("Enqueue overflow: err = %v, want ErrQueueFull", err)
	}
	if dropped != 0 {
		t.Fatalf("DropNew dropped = %d, want 0 (queue unchanged)", dropped)
	}
	// Original chunk must still be queued.
	if got := q.Bytes(); got != 4 {
		t.Fatalf("Bytes = %d, want 4 (queue unchanged on DropNew rejection)", got)
	}
}

func TestInputQueue_SingleWriteLargerThanCapacity_DropOldest(t *testing.T) {
	t.Parallel()
	q := streambuf.NewInputQueue(4, streambuf.DropOldest)
	_, _ = q.Enqueue([]byte("XX"))
	dropped, err := q.Enqueue([]byte("abcdefgh"))
	if err != nil {
		t.Fatalf("Enqueue large: %v", err)
	}
	// Both the old "XX" and the leading 4 bytes of the new chunk are
	// dropped; only the trailing capacity bytes survive.
	if dropped != 2+4 {
		t.Fatalf("dropped = %d, want 6", dropped)
	}
	chunks := q.Drain()
	if len(chunks) != 1 || string(chunks[0]) != "efgh" {
		t.Fatalf("Drain = %v, want [efgh]", chunks)
	}
}

func TestInputQueue_SingleWriteLargerThanCapacity_DropNew(t *testing.T) {
	t.Parallel()
	q := streambuf.NewInputQueue(4, streambuf.DropNew)
	_, _ = q.Enqueue([]byte("XX"))
	_, err := q.Enqueue([]byte("abcdefgh"))
	if !errors.Is(err, streambuf.ErrQueueFull) {
		t.Fatalf("Enqueue large: err = %v, want ErrQueueFull", err)
	}
	if got := q.Bytes(); got != 2 {
		t.Fatalf("Bytes = %d, want 2 (queue unchanged on rejection)", got)
	}
}

func TestInputQueue_EmptyEnqueueIsNoop(t *testing.T) {
	t.Parallel()
	q := streambuf.NewInputQueue(64, streambuf.DropOldest)
	dropped, err := q.Enqueue(nil)
	if dropped != 0 || err != nil {
		t.Fatalf("Enqueue(nil): dropped=%d err=%v", dropped, err)
	}
}

func TestInputQueue_Reset(t *testing.T) {
	t.Parallel()
	q := streambuf.NewInputQueue(64, streambuf.DropOldest)
	_, _ = q.Enqueue([]byte("payload"))
	q.Reset()
	if q.Bytes() != 0 {
		t.Fatalf("Bytes after Reset = %d, want 0", q.Bytes())
	}
}

func TestInputQueue_DrainEmptyReturnsNil(t *testing.T) {
	t.Parallel()
	q := streambuf.NewInputQueue(64, streambuf.DropOldest)
	if got := q.Drain(); got != nil {
		t.Fatalf("Drain empty = %v, want nil", got)
	}
}

func TestInputQueue_ConcurrentEnqueueDrain(t *testing.T) {
	t.Parallel()
	q := streambuf.NewInputQueue(4096, streambuf.DropOldest)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = q.Enqueue([]byte("xxxx"))
				runtime.Gosched()
			}
		}
	})
	for range 500 {
		_ = q.Drain()
	}
	close(stop)
	wg.Wait()
}
