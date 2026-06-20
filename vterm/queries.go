package vterm

// daResponder answers terminal Device Attribute queries on behalf of the
// session. mosey sits directly on the program's PTY and broadcasts raw
// bytes to attachers; a program (fish, vim, tmux, …) that probes the
// terminal with a Primary/Secondary DA query (CSI c / CSI > c) otherwise
// gets no reply — especially before any client has attached — and stalls
// or disables features.
//
// The responder scans the PTY output stream, and for each DA query it (a)
// emits a canned response to write back to the PTY, and (b) strips the
// query bytes from the passthrough output, so an attached client's own
// terminal emulator doesn't also reply (which would inject a duplicate
// response into the program's input). Every other byte and escape
// sequence passes through unchanged.
//
// Stateful queries that need the live screen (e.g. cursor-position DSR,
// CSI 6 n) are intentionally NOT handled here — they pass through to the
// attacher, whose emulator tracks the cursor and answers correctly.
type daResponder struct {
	state daState
	held  []byte // buffered "ESC [ …" while deciding whether it's a DA query
}

type daState int

const (
	daGround daState = iota
	daEsc
	daCSI
)

// da1Response is the Primary DA reply: VT220 (62) with ANSI color (22).
// da2Response is the Secondary DA reply (terminal id; version; 0).
var (
	da1Response = []byte("\x1b[?62;22c")
	da2Response = []byte("\x1b[>0;10;0c")
)

// process consumes in and returns the bytes to broadcast (out, with DA
// queries removed) plus any responses to write back to the PTY (resp).
// Both are freshly allocated, so the caller may retain them.
func (d *daResponder) process(in []byte) (out, resp []byte) {
	flushHeld := func() {
		out = append(out, d.held...)
		d.held = d.held[:0]
	}
	for _, b := range in {
		switch d.state {
		case daGround:
			if b == 0x1b {
				d.state = daEsc
				d.held = append(d.held[:0], b)
			} else {
				out = append(out, b)
			}
		case daEsc:
			if b == '[' {
				d.state = daCSI
				d.held = append(d.held, b)
			} else {
				// Not a CSI — flush ESC and reprocess b from ground.
				flushHeld()
				d.state = daGround
				if b == 0x1b {
					d.state = daEsc
					d.held = append(d.held[:0], b)
				} else {
					out = append(out, b)
				}
			}
		case daCSI:
			switch b {
			case '0', '>':
				// Possible DA parameter; keep accumulating.
				d.held = append(d.held, b)
			case 'c':
				switch string(d.held[2:]) { // params after "ESC ["
				case "", "0":
					resp = append(resp, da1Response...)
				case ">", ">0":
					resp = append(resp, da2Response...)
				default:
					// A "…c" we don't answer — pass it through intact.
					flushHeld()
					out = append(out, b)
				}
				d.held = d.held[:0]
				d.state = daGround
			default:
				// Some other CSI (SGR, DSR, …) — flush and reprocess b.
				flushHeld()
				d.state = daGround
				if b == 0x1b {
					d.state = daEsc
					d.held = append(d.held[:0], b)
				} else {
					out = append(out, b)
				}
			}
		}
	}
	return out, resp
}
