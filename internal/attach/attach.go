// Package attach dials a ship vterm peer and bridges its PTY stream
// to the local terminal.
//
// The attach side is the simpler half of ship: open a libp2p stream,
// copy bytes both ways, restore the local TTY on exit. Terminal raw
// mode is on so keystrokes flow through unmolested; the local
// process's signal-handling (Ctrl-C, etc.) hands off to the remote
// PTY, where the child program decides what to do with them.
package attach

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/term"

	"github.com/firefly-engineering/ship/internal/api"
	"github.com/firefly-engineering/ship/internal/transport"
)

// Options configures [Run].
type Options struct {
	// Host is the libp2p host the client dials from. Required.
	Host host.Host

	// Target identifies the vterm peer. Must include at least one
	// dialable multiaddr (the host's listen addrs). Required.
	Target peer.AddrInfo

	// Logger is structured-log sink. Zero means discard.
	Logger *slog.Logger

	// Stdin / Stdout / Stderr default to os.Stdin / os.Stdout /
	// os.Stderr. Tests override.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Run dials Target, opens the /ship/pty stream, and blocks until
// either side closes the stream or ctx is cancelled. Returns nil on
// a clean disconnect from the remote, otherwise the wrapped error.
func Run(ctx context.Context, opts Options) error {
	if opts.Host == nil {
		return errors.New("ship/attach: Options.Host required")
	}
	if len(opts.Target.Addrs) == 0 {
		return errors.New("ship/attach: Options.Target needs at least one multiaddr")
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

	if err := opts.Host.Connect(ctx, opts.Target); err != nil {
		return fmt.Errorf("ship/attach: connect %s: %w", opts.Target.ID, err)
	}

	// Open the control stream first so the remote has the right
	// PTY size before any bytes flow on /pty/. Without this, full-
	// screen TUIs (btop, htop, ncurses apps) read ws_col=0 and
	// bail. Older vterms that don't advertise the control protocol
	// fall through with control==nil — we still attach, just
	// without size / signal forwarding.
	control, err := newControlClient(ctx, opts.Host, opts.Target, logger)
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

	stream, err := opts.Host.NewStream(ctx, opts.Target.ID, api.ProtoPTY)
	if err != nil {
		return fmt.Errorf("ship/attach: open %s: %w", api.ProtoPTY, err)
	}
	defer func() { _ = stream.Reset() }()

	logger.Info("attached", "peer", opts.Target.ID, "protocol", api.ProtoPTY)

	// Put local stdin into raw mode so keystrokes pass through to
	// the remote PTY untouched. Only do this if stdin is an actual
	// TTY — tests / piped input skip it.
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		state, err := term.MakeRaw(int(f.Fd()))
		if err != nil {
			return fmt.Errorf("ship/attach: make raw: %w", err)
		}
		defer func() { _ = term.Restore(int(f.Fd()), state) }()
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(stdout, stream)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(stream, stdin)
		errc <- err
	}()

	select {
	case err := <-errc:
		if transport.IsExpectedShutdown(err) {
			return nil
		}
		return fmt.Errorf("ship/attach: stream: %w", err)
	case <-ctx.Done():
		return ctx.Err()
	}
}
