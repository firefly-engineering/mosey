package transport_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/firefly-engineering/mosey/transport"
)

func TestIsExpectedShutdown(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, true},
		{"io.EOF", io.EOF, true},
		{"network.ErrReset", network.ErrReset, true},
		{"wrapped ErrReset", fmt.Errorf("io: %w", network.ErrReset), true},
		{"context canceled", context.Canceled, true},
		{"deadline exceeded", context.DeadlineExceeded, true},
		{"go away string", errors.New("connection closed (local): sent go away, code: 0"), true},
		{"stream reset string", errors.New("stream reset (remote): code: 0x0: transport error"), true},
		{"closed network conn", errors.New("read tcp 127.0.0.1: use of closed network connection"), true},
		{"random error", errors.New("genuine fault"), false},
		{"file not found", errors.New("no such file"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := transport.IsExpectedShutdown(tc.err); got != tc.want {
				t.Errorf("IsExpectedShutdown(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
