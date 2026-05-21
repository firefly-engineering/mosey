// Package api carries the wire-level constants shared between vterm
// and attach. Protocol IDs live here so a typo in one binary can't
// silently miss a stream handler in the other.
package api

import "github.com/libp2p/go-libp2p/core/protocol"

// Protocol IDs follow libp2p convention: a path-shaped string with
// embedded major/minor version. Bumping the trailing number
// reserves the right to ship a breaking wire change while older
// peers continue to negotiate the previous version.
const (
	// ProtoPTY is the bidirectional PTY byte stream. Attach opens
	// this on the vterm host; vterm copies bytes between the stream
	// and the child process's PTY master.
	ProtoPTY protocol.ID = "/ship/pty/1.0.0"
)
