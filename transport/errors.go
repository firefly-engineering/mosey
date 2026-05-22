package transport

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/libp2p/go-libp2p/core/network"
)

// IsExpectedShutdown reports whether err is a normal-lifecycle
// signal that one side of a libp2p connection or stream is going
// away. Returning true is the cue for caller code to log at debug
// (or not at all) and skip "stream reset by remote" — type error
// messages that would otherwise scare users on a clean exit.
//
// Matches:
//   - nil (treated as clean shutdown)
//   - [io.EOF], [network.ErrReset]
//   - [context.Canceled], [context.DeadlineExceeded]
//   - libp2p's wrapped shutdown errors that don't sentinel-match
//     ("sent go away", "connection closed", "stream reset",
//     "use of closed network connection"). These come back from
//     various muxers (yamux, libp2p-quic, sometimes wrapped via
//     fmt.Errorf) without a clean unwrap chain, so substring
//     matching is the pragmatic option.
func IsExpectedShutdown(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) ||
		errors.Is(err, network.ErrReset) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	for _, sub := range shutdownErrorSubstrings {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}

var shutdownErrorSubstrings = []string{
	"sent go away",
	"connection closed",
	"stream reset",
	"use of closed network connection",
}
