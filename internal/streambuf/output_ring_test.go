package streambuf_test

import (
	"errors"
	"runtime"
	"sync"
	"testing"

	"github.com/firefly-engineering/ship/internal/streambuf"
)

func TestOutputRing_DefaultCapacity(t *testing.T) {
	t.Parallel()
	r := streambuf.NewOutputRing(0)
	if got, want := r.Capacity(), streambuf.DefaultOutputRingBytes; got != want {
		t.Fatalf("Capacity = %d, want %d", got, want)
	}
}

func TestOutputRing_WriteFromRoundTrip(t *testing.T) {
	t.Parallel()
	r := streambuf.NewOutputRing(64)
	seq, n := r.Write([]byte("hello"))
	if seq != 1 || n != 5 {
		t.Fatalf("Write: seq=%d n=%d, want 1,5", seq, n)
	}
	data, next, err := r.From(0)
	if err != nil {
		t.Fatalf("From(0): %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("From(0) = %q, want hello", data)
	}
	if next != 6 {
		t.Fatalf("nextSeq = %d, want 6", next)
	}
}

func TestOutputRing_SequenceAdvancesAcrossWrites(t *testing.T) {
	t.Parallel()
	r := streambuf.NewOutputRing(64)
	if seq, _ := r.Write([]byte("aa")); seq != 1 {
		t.Fatalf("write 1 seq = %d, want 1", seq)
	}
	if seq, _ := r.Write([]byte("bbb")); seq != 3 {
		t.Fatalf("write 2 seq = %d, want 3", seq)
	}
	state := r.State()
	if state.FirstSeq != 1 || state.NextSeq != 6 || state.Bytes != 5 {
		t.Fatalf("State = %+v, want first=1 next=6 bytes=5", state)
	}
}

func TestOutputRing_FromMidStreamResumes(t *testing.T) {
	t.Parallel()
	r := streambuf.NewOutputRing(64)
	_, _ = r.Write([]byte("aaaa"))   // seqs 1..4
	_, _ = r.Write([]byte("bbbbbb")) // seqs 5..10

	data, next, err := r.From(5)
	if err != nil {
		t.Fatalf("From(5): %v", err)
	}
	if string(data) != "bbbbbb" {
		t.Fatalf("From(5) = %q, want bbbbbb", data)
	}
	if next != 11 {
		t.Fatalf("nextSeq = %d, want 11", next)
	}
}

func TestOutputRing_FromAtCurrentReturnsNil(t *testing.T) {
	t.Parallel()
	r := streambuf.NewOutputRing(64)
	_, _ = r.Write([]byte("aaaa"))
	data, next, err := r.From(5)
	if err != nil {
		t.Fatalf("From(5): %v", err)
	}
	if data != nil {
		t.Fatalf("From(at next): want nil, got %q", data)
	}
	if next != 5 {
		t.Fatalf("nextSeq = %d, want 5", next)
	}
}

func TestOutputRing_FromOlderReturnsSeqBehindRing(t *testing.T) {
	t.Parallel()
	r := streambuf.NewOutputRing(4)
	_, _ = r.Write([]byte("aaaa"))   // seqs 1..4
	_, _ = r.Write([]byte("bbbbbb")) // evicts the aaaa run

	data, next, err := r.From(1)
	if !errors.Is(err, streambuf.ErrSeqBehindRing) {
		t.Fatalf("From(1): err = %v, want ErrSeqBehindRing", err)
	}
	if next != 11 {
		t.Fatalf("nextSeq = %d, want 11", next)
	}
	// Still returns the retained window so callers can do best-effort
	// replay with a warning.
	if len(data) != 4 {
		t.Fatalf("retained bytes = %d, want 4", len(data))
	}
}

func TestOutputRing_EvictsOldestOnOverflow(t *testing.T) {
	t.Parallel()
	r := streambuf.NewOutputRing(8)
	_, _ = r.Write([]byte("12345")) // seqs 1..5
	_, _ = r.Write([]byte("6789"))  // seqs 6..9; evicts 1 byte (the leading "1")

	data, next, err := r.From(0)
	if err != nil {
		t.Fatalf("From(0): %v", err)
	}
	if string(data) != "23456789" {
		t.Fatalf("data = %q, want 23456789", data)
	}
	if next != 10 {
		t.Fatalf("nextSeq = %d, want 10", next)
	}
	state := r.State()
	if state.FirstSeq != 2 {
		t.Fatalf("FirstSeq = %d, want 2 (one byte evicted)", state.FirstSeq)
	}
}

func TestOutputRing_SingleWriteLargerThanCapacity(t *testing.T) {
	t.Parallel()
	r := streambuf.NewOutputRing(4)
	seq, n := r.Write([]byte("abcdefgh"))
	if seq != 1 || n != 8 {
		t.Fatalf("Write: seq=%d n=%d, want 1,8", seq, n)
	}
	data, _, err := r.From(0)
	if err != nil {
		t.Fatalf("From(0): %v", err)
	}
	if string(data) != "efgh" {
		t.Fatalf("data = %q, want efgh", data)
	}
	state := r.State()
	if state.FirstSeq != 5 {
		t.Fatalf("FirstSeq = %d, want 5", state.FirstSeq)
	}
}

func TestOutputRing_WriteEmpty(t *testing.T) {
	t.Parallel()
	r := streambuf.NewOutputRing(16)
	seq, n := r.Write(nil)
	if seq != 1 || n != 0 {
		t.Fatalf("Write(nil): seq=%d n=%d, want 1,0", seq, n)
	}
}

func TestOutputRing_Reset(t *testing.T) {
	t.Parallel()
	r := streambuf.NewOutputRing(16)
	_, _ = r.Write([]byte("xxx"))
	r.Reset()
	if state := r.State(); state.FirstSeq != 1 || state.Bytes != 0 {
		t.Fatalf("State after Reset = %+v, want first=1 bytes=0", state)
	}
}

func TestOutputRing_ConcurrentWriteFrom(t *testing.T) {
	t.Parallel()
	r := streambuf.NewOutputRing(1024)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = r.Write([]byte("xxxx"))
				runtime.Gosched()
			}
		}
	})
	for range 1000 {
		_, _, _ = r.From(0)
	}
	close(stop)
	wg.Wait()
}
