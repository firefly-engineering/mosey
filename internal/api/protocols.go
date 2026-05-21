// Package api carries the wire-level constants shared between vterm
// and attach. Protocol IDs live here so a typo in one binary can't
// silently miss a stream handler in the other.
//
//go:generate protoc --go_out=../../ --go_opt=module=github.com/firefly-engineering/ship control.proto
package api

// Protocol IDs are plain strings so any backend (libp2p, http2,
// websocket) can hand them off to its own protocol-negotiation
// layer. The path shape (`/ship/<feature>/<major>.<minor>.<patch>`)
// follows libp2p convention; bumping the trailing number reserves
// the right to ship a breaking wire change while older peers
// continue to negotiate the previous version.
const (
	// ProtoPTY is the bidirectional PTY byte stream. Attach opens
	// this on the vterm host; vterm copies bytes between the stream
	// and the child process's PTY master.
	ProtoPTY = "/ship/pty/1.0.0"

	// ProtoControl carries length-delimited [ControlMessage] frames
	// between the vterm and any attached clients. v1 messages:
	// Resize (window size change) and Signal (process signal
	// forwarding). The stream is bidi so v2 can layer state events
	// from vterm → attach without changing the negotiated protocol.
	ProtoControl = "/ship/control/1.0.0"
)
