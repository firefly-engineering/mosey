package http2_test

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/transport"
	"github.com/firefly-engineering/mosey/transport/http2"
)

// TestBackend_RoundTrip stands up a single backend bound to a
// random loopback port, registers an echo handler on a protocol id,
// and exercises a full bidi exchange via Dial. Catches the common
// HTTP/2 streaming pitfalls (response delayed until request body
// completes, server-side buffering, half-close semantics).
func TestBackend_RoundTrip(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server, err := http2.New(ctx, http2.Options{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	defer func() { _ = server.Close() }()

	const proto = "/test/echo/1.0.0"
	echoed := make(chan struct{}, 1)
	server.Handle(proto, func(s transport.Stream) {
		defer func() { _ = s.Close() }()
		buf := make([]byte, 1024)
		for {
			n, err := s.Read(buf)
			if n > 0 {
				if _, werr := s.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					echoed <- struct{}{}
				}
				return
			}
		}
	})

	endpoints := server.Endpoints()
	if len(endpoints) == 0 {
		t.Fatal("server published no endpoints")
	}

	client, err := http2.New(ctx, http2.Options{}) // client-only
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer func() { _ = client.Close() }()

	stream, err := client.Dial(ctx, endpoints[0], proto)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = stream.Close() }()

	// Send a few rounds; verify each one echoes back before sending
	// the next, so we'd catch response-side buffering.
	for _, line := range []string{"alpha", "beta", "gamma"} {
		if _, err := stream.Write([]byte(line)); err != nil {
			t.Fatalf("write %q: %v", line, err)
		}
		got := make([]byte, len(line))
		if _, err := io.ReadFull(stream, got); err != nil {
			t.Fatalf("read echo of %q: %v", line, err)
		}
		if string(got) != line {
			t.Errorf("echo mismatch: got %q, want %q", got, line)
		}
	}

	// Half-close write side; server should see EOF on its Read.
	hc, ok := stream.(transport.HalfCloser)
	if !ok {
		t.Fatalf("http2 client stream should implement transport.HalfCloser")
	}
	if err := hc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	select {
	case <-echoed:
	case <-time.After(3 * time.Second):
		t.Fatal("server never observed EOF on request body after CloseWrite")
	}
}

// TestBackend_UnregisteredProtocolReturnsError verifies the server
// rejects unknown protocols with a 404 → wrapped error on the
// client side. Mirrors libp2p's "protocol not supported" behavior
// so the attach-side fallback for missing /mosey/control/ keeps
// working with this backend too.
func TestBackend_UnregisteredProtocolReturnsError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server, err := http2.New(ctx, http2.Options{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	defer func() { _ = server.Close() }()

	client, err := http2.New(ctx, http2.Options{})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Dial(ctx, server.Endpoints()[0], "/nothing/registered/1.0.0")
	if err == nil {
		t.Fatal("Dial on unregistered protocol must return an error")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected error to mention 404 status; got %v", err)
	}
}

// TestBackend_MultipleStreamsOverOneConnection opens several
// concurrent streams to the same server. HTTP/2 multiplexes them
// over a single TCP connection; the test makes sure the handler
// runs them in parallel without one stream's bytes leaking into
// another.
func TestBackend_MultipleStreamsOverOneConnection(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server, err := http2.New(ctx, http2.Options{ListenAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	defer func() { _ = server.Close() }()

	const proto = "/test/echo-tagged/1.0.0"
	server.Handle(proto, func(s transport.Stream) {
		defer func() { _ = s.Close() }()
		buf := make([]byte, 1024)
		for {
			n, err := s.Read(buf)
			if n > 0 {
				_, _ = s.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	})

	client, err := http2.New(ctx, http2.Options{})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer func() { _ = client.Close() }()

	endpoint := server.Endpoints()[0]
	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(tag byte) {
			defer wg.Done()
			s, err := client.Dial(ctx, endpoint, proto)
			if err != nil {
				errCh <- err
				return
			}
			defer func() { _ = s.Close() }()
			payload := []byte{tag, tag, tag, tag}
			if _, err := s.Write(payload); err != nil {
				errCh <- err
				return
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(s, got); err != nil {
				errCh <- err
				return
			}
			for _, b := range got {
				if b != tag {
					errCh <- io.ErrUnexpectedEOF // distinguishable
					return
				}
			}
		}(byte('a' + i))
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent stream: %v", err)
	}
}
