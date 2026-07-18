// Package streambuf holds the bounded-buffer primitives the stream-agent
// uses for disconnection tolerance, per
// docs/src/internals/process-model.md "Disconnection tolerance".
//
// One type lives here:
//
//   - [OutputRing] — a sequence-numbered ring buffer of agent → pane
//     output bytes. Owned by shepherd-d for as long as the agent is
//     running; replayed on reattach so a brief network blip or a
//     daemon-side relay restart doesn't lose rendered output.
//
// The wire format that resumes a session (PaneAttach.resume_seq plus
// AgentReady.first_seq / next_seq) lives in
// internal/api/v1/shepherd.proto; the relay glue that actually pumps
// bytes through this buffer is added by shep-d3f.7 (libp2p relay) on
// top of the v0.2 attach skeleton (shep-d3f.3). The type itself
// is kept self-contained and unit-testable so the wiring layer is a
// thin straightforward addition rather than a redesign.
//
// Defaults are documented on the constructors and exported as
// constants so callers can override them (and tests can pin small
// values). Drop policy is "oldest first" everywhere — same shape as
// scrape.BufferSource and the same shape as a terminal scrollback.
package streambuf
