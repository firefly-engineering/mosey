// Package attach dials a mosey vterm peer and bridges its PTY
// stream to the local terminal.
//
// Stream lifecycle: open /mosey/pty/ via the transport, copy bytes
// both ways, restore the local TTY on exit. Terminal raw mode is
// on so keystrokes flow through unmolested; the local process's
// signal-handling (Ctrl-C, etc.) hands off to the remote PTY,
// where the child program decides what to do with them.
//
// On a non-fatal stream close (network blip, server-side eviction
// that wasn't us asking) we don't bail — we open a fresh
// /mosey/pty-resume/ stream with the local last-rendered byte
// count, and the vterm replays any bytes we missed from its
// OutputRing.
package attach

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/term"

	"github.com/firefly-engineering/mosey/api"
	"github.com/firefly-engineering/mosey/transport"
)

// errPrefix tags errors emitted by this package. Shared by
// attach.go and control.go so both surfaces attribute consistently.
const errPrefix = "mosey/attach: "

// reconnectInitialDelay / Max bound the exponential backoff used
// by the resume loop. Real failures (auth rejected, bad endpoint)
// surface quickly; transient blips wait a beat and retry.
const (
	reconnectInitialDelay = 200 * time.Millisecond
	reconnectMaxDelay     = 5 * time.Second
)

// Options configures [Run].
type Options struct {
	// Transport is the wire backend used to dial Target. Required.
	Transport transport.Transport

	// Target is the endpoint (URI form) of the vterm to attach to.
	// Format depends on the transport (libp2p multiaddr,
	// https://… URL, etc.). Required.
	Target string

	// Logger is structured-log sink. Zero means discard.
	Logger *slog.Logger

	// Stdin / Stdout / Stderr default to os.Stdin / os.Stdout /
	// os.Stderr. Tests override.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Run dials Target, opens the /mosey/pty stream, and blocks until
// ctx is cancelled or the session ends fatally. Reconnects across
// transient stream closures using /mosey/pty-resume/ so a brief
// network blip doesn't black-screen the user.
func Run(ctx context.Context, opts Options) error {
	if opts.Transport == nil {
		return errors.New(errPrefix + "Options.Transport required")
	}
	if opts.Target == "" {
		return errors.New(errPrefix + "Options.Target required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	stdin := opts.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	stdout := opts.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}

	// Open the control stream first so the remote has the right
	// PTY size before any bytes flow on /pty/. Older vterms that
	// don't advertise the control protocol fall through with
	// control==nil — we still attach, just without size / signal
	// forwarding.
	control, err := newControlClient(ctx, opts.Transport, opts.Target, logger)
	if err != nil {
		return err
	}
	if control != nil {
		defer func() { _ = control.Close() }()
		if cols, rows, sizeErr := localTerminalSize(stdin); sizeErr == nil && cols > 0 && rows > 0 {
			if err := control.SendResize(cols, rows); err != nil {
				logger.Warn("initial resize", "err", err)
			}
		}
		go watchSIGWINCH(ctx, stdin, control, logger)
	}

	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		state, err := term.MakeRaw(int(f.Fd()))
		if err != nil {
			return fmt.Errorf(errPrefix+"make raw: %w", err)
		}
		defer func() { _ = term.Restore(int(f.Fd()), state) }()
	}

	// Tracks the last byte we've rendered on local stdout. On
	// reconnect we pass this to /mosey/pty-resume/ so the vterm
	// replays anything we missed during the dropout.
	var renderedBytes atomic.Uint64

	// First connect uses /mosey/pty/; subsequent reconnects use
	// /mosey/pty-resume/ with the accumulated seq.
	proto := api.ProtoPTY
	delay := reconnectInitialDelay
	for {
		fromSeq := renderedBytes.Load()
		stream, err := dialPTY(ctx, opts.Transport, opts.Target, proto, fromSeq)
		if err != nil {
			if isFatalDialError(err) || ctx.Err() != nil {
				return err
			}
			logger.Warn(errPrefix+"dial failed, retrying", "err", err, "in", delay)
			if waitForDelayOrCtx(ctx, delay) != nil {
				return ctx.Err()
			}
			delay = nextDelay(delay)
			continue
		}
		logger.Info("attached", "target", opts.Target, "protocol", proto, "resume_seq", fromSeq)
		delay = reconnectInitialDelay

		// Re-send the resize now that the PTY stream is open. The
		// pre-PTY resize sent above arrives at the vterm before
		// the sessionClient for this remote exists (it's created
		// by /mosey/pty attach), so it gets dropped with
		// "resize: no PTY client for remote". Re-sending here
		// catches the same geometry against a now-registered
		// client. Cheap and idempotent.
		if control != nil {
			if cols, rows, sizeErr := localTerminalSize(stdin); sizeErr == nil && cols > 0 && rows > 0 {
				if err := control.SendResize(cols, rows); err != nil {
					logger.Warn("post-attach resize", "err", err)
				}
			}
		}

		err = pumpStream(ctx, stream, stdin, stdout, &renderedBytes)
		_ = stream.Close()

		if err == nil || transport.IsExpectedShutdown(err) {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		logger.Warn(errPrefix+"stream ended, reconnecting", "err", err, "resume_seq", renderedBytes.Load())
		proto = api.ProtoPTYResume
	}
}

// dialPTY opens the PTY stream. For ProtoPTYResume it writes the
// initial varint resume_seq header before returning the stream so
// pumpStream can treat it as raw bytes from there on.
func dialPTY(ctx context.Context, tr transport.Transport, target, proto string, resumeSeq uint64) (transport.Stream, error) {
	stream, err := tr.Dial(ctx, target, proto)
	if err != nil {
		return nil, fmt.Errorf(errPrefix+"open %s: %w", proto, err)
	}
	if proto == api.ProtoPTYResume {
		if _, err := stream.Write(encodeVarint(resumeSeq)); err != nil {
			_ = stream.Close()
			return nil, fmt.Errorf(errPrefix+"send resume header: %w", err)
		}
	}
	return stream, nil
}

// pumpStream runs the bidi copy until either side errors. Returns
// nil on a clean EOF, otherwise the wrapped error.
func pumpStream(ctx context.Context, stream transport.Stream, stdin io.Reader, stdout io.Writer, rendered *atomic.Uint64) error {
	errc := make(chan error, 2)
	// Output: stream → stdout, tracking byte count in rendered.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if _, werr := stdout.Write(buf[:n]); werr != nil {
					errc <- werr
					return
				}
				rendered.Add(uint64(n))
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()
	// Input: stdin → stream.
	go func() {
		_, err := io.Copy(stream, stdin)
		errc <- err
	}()
	select {
	case err := <-errc:
		if err == io.EOF {
			return nil
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// isFatalDialError returns true for errors that won't go away with
// a retry — bad endpoint format, auth rejected, ctx already done.
// Transient errors (network unavailable, peer down) return false
// and the reconnect loop backs off.
func isFatalDialError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// Heuristic: anything that mentions "unauthoriz" / "unsupported"
	// is fatal. Reconnect loop only helps with network blips, not
	// config errors.
	msg := err.Error()
	for _, sub := range []string{"unauthorized", "unsupported scheme", "missing host", "missing scheme"} {
		if contains(msg, sub) {
			return true
		}
	}
	return false
}

// nextDelay applies exponential backoff with a fixed cap.
func nextDelay(d time.Duration) time.Duration {
	d *= 2
	if d > reconnectMaxDelay {
		d = reconnectMaxDelay
	}
	return d
}

// waitForDelayOrCtx returns nil after d, or ctx.Err() when ctx
// fires first.
func waitForDelayOrCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// encodeVarint mirrors the encoder in internal/vterm/session.go.
// Duplicated here so internal/attach doesn't take a dep on
// internal/vterm; both sides have to agree on the same wire format
// regardless.
func encodeVarint(v uint64) []byte {
	var out [10]byte
	i := 0
	for v >= 0x80 {
		out[i] = byte(v) | 0x80
		v >>= 7
		i++
	}
	out[i] = byte(v)
	return out[:i+1]
}

// contains is a tiny inline substring check — strings.Contains
// would be one more import for one call.
func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
