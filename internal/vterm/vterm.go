// Package vterm runs a child program under a PTY and serves its
// terminal stream over a [transport.Transport] to one or more
// concurrent attached clients.
//
// One Session owns one process and one PTY. The transport accepts
// inbound /ship/pty/ streams; the session's mode (Supersede,
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

	"github.com/firefly-engineering/ship/internal/api"
	"github.com/firefly-engineering/ship/internal/streambuf"
	"github.com/firefly-engineering/ship/internal/transport"
)

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

	mu       sync.Mutex
	nextID   int64
	clients  map[int64]*sessionClient
	writerID int64 // PrimaryObserver writer-seat owner; 0 = vacant
}

// Options configures [Run]. Transport is required; the rest pick
// sensible defaults.
type Options struct {
	// Transport is where ship registers the /ship/pty and
	// /ship/control handlers. Required; lifetime is the caller's.
	Transport transport.Transport

	// Logger is structured-log sink. Zero means discard.
	Logger *slog.Logger

	// Mode controls multi-client behavior. Zero / ModeUnspecified
	// defaults to ModeSupersede — the friendliest setting that
	// avoids race conditions and matches "I roam between
	// machines" usage.
	Mode Mode
}

// Run spawns argv under a PTY, registers the protocol handlers on
// opts.Transport, and blocks until the child exits, ctx is
// cancelled, or the transport shuts down. Returns the child's
// exit code via the embedded [*exec.ExitError] when applicable.
func Run(ctx context.Context, opts Options, argv []string) error {
	if opts.Transport == nil {
		return errors.New("ship/vterm: Options.Transport required")
	}
	if len(argv) == 0 {
		return errors.New("ship/vterm: argv must contain the program to run")
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
		return fmt.Errorf("ship/vterm: pty.Start: %w", err)
	}

	sess := &Session{
		logger:  logger,
		tr:      opts.Transport,
		cmd:     cmd,
		ptyf:    ptmx,
		mode:    mode,
		output:  newOutputRing(),
		clients: map[int64]*sessionClient{},
	}

	opts.Transport.Handle(api.ProtoPTY, sess.handlePTY)
	opts.Transport.Handle(api.ProtoControl, sess.handleControl)
	defer opts.Transport.Unhandle(api.ProtoPTY)
	defer opts.Transport.Unhandle(api.ProtoControl)

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
		return fmt.Errorf("ship/vterm: child wait: %w", waitErr)
	}
	logger.Info("vterm child exited", "code", 0)
	return nil
}

// handlePTY is the transport handler for [api.ProtoPTY]. Admits
// the client via the mode-aware addClient gate, then drives two
// goroutines: output drains the per-client outCh to the stream,
// input drains the stream to the PTY (when permitted).
func (s *Session) handlePTY(stream transport.Stream) {
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
	)
	defer s.logger.Info("attach closed", "peer", remote, "client_id", client.id)

	// Send initial replay so the client sees current screen state
	// even if it attached mid-session. Wrapped in a goroutine via
	// outCh so it interleaves correctly with live bytes.
	if replay, _, err := s.output.From(0); err == nil && len(replay) > 0 {
		select {
		case client.outCh <- replay:
		default:
			// Initial buffer full somehow — happens only when
			// outCh size < replay size, which is a misconfig.
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
