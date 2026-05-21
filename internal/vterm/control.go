package vterm

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/creack/pty"
	"google.golang.org/protobuf/encoding/protodelim"

	"github.com/firefly-engineering/ship/internal/api"
	"github.com/firefly-engineering/ship/internal/auth"
	"github.com/firefly-engineering/ship/internal/transport"
)

// handleControl is the transport handler for [api.ProtoControl].
// Reads length-delimited [api.ControlMessage] frames and dispatches
// each to the live PTY / child process. Returns when the peer
// closes its write side, the stream errors, or the service is torn
// down. Always Closes the stream — backends decide whether that
// translates to a clean half-close or a forceful tear-down.
func (s *Session) handleControl(stream transport.Stream) {
	remote := stream.RemoteID()
	identity := auth.IdentityOf(stream)
	s.logger.Info("control opened", "peer", remote, "role", identity.Label)
	defer func() {
		_ = stream.Close()
		s.logger.Info("control closed", "peer", remote)
	}()

	reader := newDelimReader(stream)
	for {
		var msg api.ControlMessage
		if err := protodelim.UnmarshalFrom(reader, &msg); err != nil {
			if !transport.IsExpectedShutdown(err) {
				s.logger.Warn("control read", "peer", remote, "err", err)
			}
			return
		}
		switch payload := msg.GetPayload().(type) {
		case *api.ControlMessage_Resize:
			if !identity.CanResize() {
				s.logger.Debug("control resize denied (no Resize cap)", "peer", remote, "role", identity.Label)
				continue
			}
			if err := s.applyResize(payload.Resize); err != nil {
				s.logger.Warn("control resize", "peer", remote, "err", err)
			}
		case *api.ControlMessage_Signal:
			if !identity.CanWrite() {
				s.logger.Debug("control signal denied (no Write cap)", "peer", remote, "role", identity.Label)
				continue
			}
			if err := s.applySignal(payload.Signal); err != nil {
				s.logger.Warn("control signal", "peer", remote, "err", err)
			}
		default:
			s.logger.Warn("control: unknown payload", "peer", remote, "type", fmt.Sprintf("%T", payload))
		}
	}
}

// applyResize updates the PTY winsize via TIOCSWINSZ. cols/rows = 0
// is rejected — the kernel allows it but it puts curses apps into
// a "size unknown" state that's worse than the previous size.
func (s *Session) applyResize(r *api.Resize) error {
	cols, rows := r.GetCols(), r.GetRows()
	if cols == 0 || rows == 0 {
		return fmt.Errorf("resize ignored: zero dimension (cols=%d rows=%d)", cols, rows)
	}
	if err := pty.Setsize(s.ptyf, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}); err != nil {
		return fmt.Errorf("setsize: %w", err)
	}
	s.logger.Debug("pty resized", "cols", cols, "rows", rows)
	return nil
}

// applySignal forwards a constrained signal kind to the child
// process group. The allow-list is small on purpose; widening it
// requires a per-vterm authn check that v1 doesn't have.
func (s *Session) applySignal(sig *api.Signal) error {
	var os_signal os.Signal
	switch sig.GetKind() {
	case api.Signal_KIND_HUP:
		os_signal = syscall.SIGHUP
	case api.Signal_KIND_INT:
		os_signal = syscall.SIGINT
	case api.Signal_KIND_TERM:
		os_signal = syscall.SIGTERM
	case api.Signal_KIND_USR1:
		os_signal = syscall.SIGUSR1
	case api.Signal_KIND_USR2:
		os_signal = syscall.SIGUSR2
	default:
		return fmt.Errorf("signal kind %v not allowed", sig.GetKind())
	}
	if s.cmd == nil || s.cmd.Process == nil {
		return errors.New("signal: child process not running")
	}
	if err := s.cmd.Process.Signal(os_signal); err != nil {
		return fmt.Errorf("signal child: %w", err)
	}
	s.logger.Debug("signal forwarded", "signal", os_signal.String())
	return nil
}

// delimReader is a tiny adapter to satisfy [protodelim.Reader] from
// an [io.Reader]. protodelim requires a ByteReader for the varint
// length prefix; libp2p streams only expose [io.Reader], so we wrap
// with a [bufio.Reader]-like single-byte adapter.
type delimReader struct {
	r io.Reader
	b [1]byte
}

func newDelimReader(r io.Reader) *delimReader { return &delimReader{r: r} }

func (d *delimReader) Read(p []byte) (int, error) { return d.r.Read(p) }

func (d *delimReader) ReadByte() (byte, error) {
	n, err := io.ReadFull(d.r, d.b[:])
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, io.ErrUnexpectedEOF
	}
	return d.b[0], nil
}
