// Package vterm runs a child program under a PTY and serves its
// terminal stream over libp2p.
//
// One Service owns one process. The libp2p host can accept multiple
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
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"

	"github.com/firefly-engineering/ship/internal/api"
)

// Service is a running vterm: a child process under a PTY plus the
// libp2p stream handler that bridges it to attachers.
type Service struct {
	logger *slog.Logger
	host   host.Host
	cmd    *exec.Cmd
	ptyf   *os.File // master end of the PTY pair (creack/pty returns an *os.File)

	// closeOnce guards Close so the registered stream handler can
	// safely call it from a goroutine on error.
	closeOnce sync.Once
}

// Options configures [Run]. All fields except Host are optional.
type Options struct {
	// Host is the libp2p host serving the vterm. Required; lifetime
	// is the caller's responsibility (vterm doesn't close it on
	// teardown).
	Host host.Host

	// Logger is structured-log sink. Zero means discard.
	Logger *slog.Logger
}

// Run spawns argv under a PTY, registers the /ship/pty handler on
// opts.Host, and blocks until the child exits, ctx is cancelled, or
// the host shuts down. Returns the child's exit code via the
// embedded [*exec.ExitError] when applicable.
func Run(ctx context.Context, opts Options, argv []string) error {
	if opts.Host == nil {
		return errors.New("ship/vterm: Options.Host required")
	}
	if len(argv) == 0 {
		return errors.New("ship/vterm: argv must contain the program to run")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// Pipe the child's signals to a new process group so we can kill
	// the whole tree on teardown rather than orphan grandchildren.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	// Default the PTY to 80x24. Without this, ncurses-style TUIs
	// (btop, htop) read ws_col=0 / ws_row=0 from the freshly-opened
	// PTY and bail before drawing a frame. Attach overrides this
	// with a Resize control message at connect time, but the child
	// might already have queried the size by then. 80x24 is the
	// historical default and looks fine for most apps until the
	// real size lands.
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: 80, Rows: 24})
	if err != nil {
		return fmt.Errorf("ship/vterm: pty.Start: %w", err)
	}

	svc := &Service{
		logger: logger,
		host:   opts.Host,
		cmd:    cmd,
		ptyf:   ptmx,
	}

	opts.Host.SetStreamHandler(api.ProtoPTY, svc.handlePTY)
	opts.Host.SetStreamHandler(api.ProtoControl, svc.handleControl)
	defer opts.Host.RemoveStreamHandler(api.ProtoPTY)
	defer opts.Host.RemoveStreamHandler(api.ProtoControl)

	logger.Info("vterm running",
		"pid", cmd.Process.Pid,
		"argv", argv,
		"peer_id", opts.Host.ID(),
	)

	// Wait for the child to exit; ctx cancellation is propagated to
	// the child via exec.CommandContext.
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

// handlePTY is the libp2p stream handler for [api.ProtoPTY]. It
// runs two goroutines — pty→stream and stream→pty — and returns
// when either direction errors. The stream is reset on exit so the
// peer notices the disconnect.
func (s *Service) handlePTY(stream network.Stream) {
	remote := stream.Conn().RemotePeer()
	s.logger.Info("attach opened", "peer", remote)
	defer func() {
		_ = stream.Reset()
		s.logger.Info("attach closed", "peer", remote)
	}()

	// Output: pty -> stream. The PTY master file is shared across
	// every attacher; reads race so one attacher gets each byte. For
	// v1's single-attacher case this is fine; multi-attacher will
	// move output through an [internal/streambuf.OutputRing] fanned
	// to every connected stream.
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, s.ptyf)
		errc <- err
	}()
	// Input: stream -> pty.
	go func() {
		_, err := io.Copy(s.ptyf, stream)
		errc <- err
	}()

	err := <-errc
	if err != nil && !errors.Is(err, io.EOF) {
		s.logger.Warn("attach stream error", "peer", remote, "err", err)
	}
}
