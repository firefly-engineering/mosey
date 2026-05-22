// Package api carries the wire-level constants shared between vterm
// and attach. Protocol IDs live here so a typo in one binary can't
// silently miss a stream handler in the other.
//
// The protocol-ID strings below are a commitment, not an
// implementation detail: once any workspace has handshaked against
// them they are baked into key derivation and every peer's
// expectation of what bytes mean. Bumping the trailing version
// number is the sanctioned way to change them; renaming a constant
// without a version bump silently breaks every existing workspace.
//
//go:generate protoc --go_out=../ --go_opt=module=github.com/firefly-engineering/mosey control.proto
package api

// Protocol IDs are plain strings so any backend (libp2p, http2,
// websocket) can hand them off to its own protocol-negotiation
// layer. The path shape (`/mosey/<feature>/<major>.<minor>.<patch>`)
// follows libp2p convention; bumping the trailing number reserves
// the right to introduce a breaking wire change while older peers
// continue to negotiate the previous version.
const (
	// ProtoAuth carries the three-message [AuthMessage] handshake
	// that proves both peers hold the workspace's shared secret.
	// Dial-side opens this first; the auth wrapper around the
	// transport only exposes application protocols to handlers
	// after a successful exchange.
	ProtoAuth = "/mosey/auth/1.0.0"

	// ProtoPTY is the bidirectional PTY byte stream. Attach opens
	// this on the vterm host; vterm copies bytes between the stream
	// and the child process's PTY master.
	ProtoPTY = "/mosey/pty/1.0.0"

	// ProtoPTYResume is the reattach variant of ProtoPTY. The
	// client's first message on the stream is a varint encoding
	// the last sequence number it rendered locally; the vterm
	// replays bytes from that point in its OutputRing before
	// streaming live output. Used by attach.Run's reconnect loop
	// so a flaky network doesn't leave the user staring at a
	// black-screened TUI.
	ProtoPTYResume = "/mosey/pty-resume/1.0.0"

	// ProtoControl carries length-delimited [ControlMessage] frames
	// between the vterm and any attached clients. v1 messages:
	// Resize (window size change) and Signal (process signal
	// forwarding). The stream is bidi so v2 can layer state events
	// from vterm → attach without changing the negotiated protocol.
	ProtoControl = "/mosey/control/1.0.0"
)
