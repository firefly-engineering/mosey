// Package vterm runs a child program under a PTY and serves its
// terminal stream over a [transport.Transport] to one or more
// concurrent attached clients.
//
// One Session owns one process and one PTY. The transport accepts
// inbound /mosey/pty/ streams; the session's mode (Supersede,
// Exclusive, PrimaryObserver, MultiWrite) decides how those
// inbound streams coexist. A single PTY-reader goroutine fans
// output out to every active client via a per-client buffered
// channel plus an OutputRing for replay-on-reconnect. Input is
// gated per-client by [auth.Identity.CanWrite] and the session's
// mode-derived write permission.
package vterm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"

	"github.com/firefly-engineering/mosey/api"
	"github.com/firefly-engineering/mosey/streambuf"
	"github.com/firefly-engineering/mosey/transport"
)

// errPrefix tags errors emitted by this package.
const errPrefix = "mosey/vterm: "

// Session is a running vterm: a child process under a PTY, plus
// the registry of currently-attached clients, plus the transport
// handlers that bridge them.
type Session struct {
	logger *slog.Logger
	tr     transport.Transport
	cmd    *exec.Cmd
	ptyf   *os.File
	mode   Mode

	// output buffers PTY → world bytes for replay when a client
	// reattaches. The live fan-out is per-client (see broadcast);
	// the ring is for clients that miss bytes due to a slow link
	// or a disconnect.
	output *streambuf.OutputRing

	// daResp answers terminal Device Attribute queries (see queries.go);
	// only touched from pumpOutput, so it needs no lock.
	daResp daResponder

	mu       sync.Mutex
	nextID   int64
	clients  map[int64]*sessionClient
	writerID int64 // PrimaryObserver writer-seat owner; 0 = vacant
	// pendingResize stashes the latest Resize the client sent on
	// /mosey/control BEFORE its /mosey/pty stream landed (or
	// after it dropped without a replacement). The next addClient
	// for the same remote applies + clears the entry. Without
	// this, the initial geometry an attach sends over the
	// control stream is dropped — control handler runs concurrently
	// with handlePTY, with no ordering guarantee.
	pendingResize map[string]pendingResize
}

// pendingResize records a Resize the session can't apply yet
// because no sessionClient exists for the originating remote.
type pendingResize struct {
	cols, rows uint32
}

// Options configures [Run]. Transport is required; the rest pick
// sensible defaults.
type Options struct {
	// Transport is where vterm registers the /mosey/pty and
	// /mosey/control handlers. Required; lifetime is the caller's.
	Transport transport.Transport

	// Logger is structured-log sink. Zero means discard.
	Logger *slog.Logger

	// Mode controls multi-client behavior. Zero / ModeUnspecified
	// defaults to ModeSupersede — the friendliest setting that
	// avoids race conditions and matches "I roam between
	// machines" usage.
	Mode Mode

	// Ready, when non-nil, is closed once Run has registered every
	// stream handler on Transport. Callers that need to dial the
	// vterm from the same process can block on this channel instead
	// of guessing a sleep — handler registration happens after
	// pty.StartWithSize, whose fork+exec latency under CPU pressure
	// is exactly the race that motivated this signal.
	Ready chan<- struct{}
}

// Run spawns argv under a PTY, registers the protocol handlers on
// opts.Transport, and blocks until the child exits, ctx is
// cancelled, or the transport shuts down. Returns the child's
// exit code via the embedded [*exec.ExitError] when applicable.
func Run(ctx context.Context, opts Options, argv []string) error {
	if opts.Transport == nil {
		return errors.New(errPrefix + "Options.Transport required")
	}
	if len(argv) == 0 {
		return errors.New(errPrefix + "argv must contain the program to run")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	mode := opts.Mode
	if mode == ModeUnspecified {
		mode = ModeSupersede
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: 80, Rows: 24})
	if err != nil {
		return fmt.Errorf(errPrefix+"pty.Start: %w", err)
	}

	sess := &Session{
		logger:        logger,
		tr:            opts.Transport,
		cmd:           cmd,
		ptyf:          ptmx,
		mode:          mode,
		output:        streambuf.NewOutputRing(outputRingCapacity),
		clients:       map[int64]*sessionClient{},
		pendingResize: map[string]pendingResize{},
	}

	opts.Transport.Handle(api.ProtoPTY, sess.handlePTY)
	opts.Transport.Handle(api.ProtoPTYResume, sess.handlePTYResume)
	opts.Transport.Handle(api.ProtoControl, sess.handleControl)
	defer opts.Transport.Unhandle(api.ProtoPTY)
	defer opts.Transport.Unhandle(api.ProtoPTYResume)
	defer opts.Transport.Unhandle(api.ProtoControl)

	if opts.Ready != nil {
		close(opts.Ready)
	}

	logger.Info("vterm running",
		"pid", cmd.Process.Pid,
		"argv", argv,
		"mode", mode,
		"endpoints", opts.Transport.Endpoints(),
	)

	// Single PTY-output goroutine fans bytes out to every
	// attached client. Exits on PTY EOF.
	go sess.pumpOutput()

	waitErr := cmd.Wait()
	sess.shutdown()
	_ = ptmx.Close()

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			logger.Info("vterm child exited", "code", exitErr.ExitCode())
			return exitErr
		}
		return fmt.Errorf(errPrefix+"child wait: %w", waitErr)
	}
	logger.Info("vterm child exited", "code", 0)
	return nil
}

// handlePTY is the transport handler for [api.ProtoPTY]. Fresh
// attach — replays from sequence 0 so the client sees the full
// retained OutputRing.
func (s *Session) handlePTY(stream transport.Stream) {
	s.bridgeClient(stream, 0)
}

// handlePTYResume is the transport handler for
// [api.ProtoPTYResume]. The client's first message on the stream
// is a varint encoding the last-rendered output sequence; we
// replay from that point so a reconnecting attach picks up where
// it left off.
func (s *Session) handlePTYResume(stream transport.Stream) {
	resume, err := readResumeSeq(stream)
	if err != nil {
		s.logger.Warn("pty-resume: bad header", "peer", stream.RemoteID(), "err", err)
		_ = stream.Close()
		return
	}
	s.bridgeClient(stream, resume)
}

// bridgeClient is the shared admission + I/O pump. fromSeq is the
// sequence-number floor for the initial replay; 0 means "everything
// the ring still has."
func (s *Session) bridgeClient(stream transport.Stream, fromSeq uint64) {
	remote := stream.RemoteID()
	client := s.addClient(stream)
	if client == nil {
		s.logger.Info("attach refused by mode", "peer", remote, "mode", s.mode)
		_ = stream.Close()
		return
	}
	defer s.removeClient(client.id)

	s.logger.Info("attach opened",
		"peer", remote,
		"role", client.identity.Label,
		"client_id", client.id,
		"can_write", client.canWrite,
		"resume_seq", fromSeq,
	)
	defer s.logger.Info("attach closed", "peer", remote, "client_id", client.id)

	// Send initial replay so the client sees current screen state
	// even if it attached mid-session. Wrapped via outCh so it
	// interleaves correctly with live bytes.
	if replay, _, err := s.output.From(fromSeq); err == nil && len(replay) > 0 {
		select {
		case client.outCh <- replay:
		default:
			client.dropped.Add(1)
		}
	}

	errc := make(chan error, 2)

	// Output: outCh → stream. Stops when done closes or the
	// stream errors.
	go func() {
		for {
			select {
			case chunk, ok := <-client.outCh:
				if !ok {
					errc <- nil
					return
				}
				if _, err := stream.Write(chunk); err != nil {
					errc <- err
					return
				}
			case <-client.done:
				errc <- nil
				return
			}
		}
	}()

	// Input: stream → PTY (or io.Discard for observers / non-writers).
	// canWrite is read under s.mu so dynamic demotions land.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				s.mu.Lock()
				canWrite := client.canWrite
				s.mu.Unlock()
				if canWrite {
					_, _ = s.ptyf.Write(buf[:n])
				}
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()

	err := <-errc
	if !transport.IsExpectedShutdown(err) && err != nil {
		s.logger.Warn("attach stream error", "peer", remote, "err", err)
	}
	_ = stream.Close()
}
