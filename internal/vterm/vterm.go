// Package vterm runs a child program under a PTY and serves its
// terminal stream over a [transport.Transport].
//
// One Service owns one process. The transport can accept multiple
// concurrent attachers — they each get bidirectional access to the
// PTY (input and output). Future revisions will treat one of those
// as "primary" for input arbitration; v1 lets bytes from any
// attacher race into the PTY (interactive single-user is the
// expected case).
package vterm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"

	"github.com/firefly-engineering/ship/internal/api"
	"github.com/firefly-engineering/ship/internal/transport"
)

// Service is a running vterm: a child process under a PTY plus the
// stream handlers registered on the transport.
type Service struct {
	logger *slog.Logger
	tr     transport.Transport
	cmd    *exec.Cmd
	ptyf   *os.File // master end of the PTY pair (creack/pty returns an *os.File)

	closeOnce sync.Once
}

// Options configures [Run]. All fields except Transport are optional.
type Options struct {
	// Transport is where ship registers the /ship/pty and
	// /ship/control handlers. Required; lifetime is the caller's
	// responsibility — vterm doesn't close it on teardown.
	Transport transport.Transport

	// Logger is structured-log sink. Zero means discard.
	Logger *slog.Logger
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

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	// Default the PTY to 80x24. Without this, ncurses-style TUIs
	// (btop, htop) read ws_col=0 / ws_row=0 from the freshly-opened
	// PTY and bail before drawing a frame. Attach overrides this
	// with a Resize control message at connect time, but the child
	// might already have queried the size by then.
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: 80, Rows: 24})
	if err != nil {
		return fmt.Errorf("ship/vterm: pty.Start: %w", err)
	}

	svc := &Service{
		logger: logger,
		tr:     opts.Transport,
		cmd:    cmd,
		ptyf:   ptmx,
	}

	opts.Transport.Handle(api.ProtoPTY, svc.handlePTY)
	opts.Transport.Handle(api.ProtoControl, svc.handleControl)
	defer opts.Transport.Unhandle(api.ProtoPTY)
	defer opts.Transport.Unhandle(api.ProtoControl)

	logger.Info("vterm running",
		"pid", cmd.Process.Pid,
		"argv", argv,
		"endpoints", opts.Transport.Endpoints(),
	)

	waitErr := cmd.Wait()
	_ = ptmx.Close()
	svc.closeOnce.Do(func() {})
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

// handlePTY is the transport handler for [api.ProtoPTY]. Two
// goroutines copy bytes in either direction; returning when one
// side reaches EOF / errors. Clean shutdown closes the stream
// (peer's read returns EOF); only true errors Reset.
func (s *Service) handlePTY(stream transport.Stream) {
	remote := stream.RemoteID()
	s.logger.Info("attach opened", "peer", remote)

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, s.ptyf)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(s.ptyf, stream)
		errc <- err
	}()

	err := <-errc
	if transport.IsExpectedShutdown(err) {
		_ = stream.Close()
	} else {
		s.logger.Warn("attach stream error", "peer", remote, "err", err)
		_ = stream.Close()
	}
	s.logger.Info("attach closed", "peer", remote)
}
