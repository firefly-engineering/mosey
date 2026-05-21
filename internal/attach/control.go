package attach

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/protodelim"

	"github.com/firefly-engineering/ship/internal/api"
)

// controlClient wraps the [api.ProtoControl] stream and exposes
// typed sends. One per attach session; closed when the session
// ends.
type controlClient struct {
	logger *slog.Logger
	stream io.ReadWriteCloser

	mu     sync.Mutex
	closed bool
}

// newControlClient opens /ship/control/ on h against target and
// returns a controlClient. Returns nil + nil error when control
// is unavailable on the remote (e.g. a v0 vterm) — the caller
// should still attach the PTY in that case, just without size /
// signal forwarding.
func newControlClient(ctx context.Context, h host.Host, target peer.AddrInfo, logger *slog.Logger) (*controlClient, error) {
	stream, err := h.NewStream(ctx, target.ID, api.ProtoControl)
	if err != nil {
		// libp2p reports "protocol not supported" when the remote
		// hasn't registered the handler. Treat that as graceful
		// degradation: we can still run the PTY-only path.
		if isProtocolNotSupported(err) {
			logger.Info("ui: control protocol not advertised by peer; running without resize / signal forwarding")
			return nil, nil
		}
		return nil, fmt.Errorf("ship/attach: open %s: %w", api.ProtoControl, err)
	}
	return &controlClient{logger: logger, stream: stream}, nil
}

// SendResize writes a Resize control message.
func (c *controlClient) SendResize(cols, rows uint32) error {
	return c.send(&api.ControlMessage{
		Payload: &api.ControlMessage_Resize{
			Resize: &api.Resize{Cols: cols, Rows: rows},
		},
	})
}

// SendSignal writes a Signal control message.
func (c *controlClient) SendSignal(kind api.Signal_Kind) error {
	return c.send(&api.ControlMessage{
		Payload: &api.ControlMessage_Signal{
			Signal: &api.Signal{Kind: kind},
		},
	})
}

func (c *controlClient) send(msg *api.ControlMessage) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("control stream closed")
	}
	if _, err := protodelim.MarshalTo(c.stream, msg); err != nil {
		return fmt.Errorf("write control: %w", err)
	}
	return nil
}

// Close closes the underlying stream. Idempotent.
func (c *controlClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.stream.Close()
}

// localTerminalSize returns the current cols / rows of the supplied
// stdin (must be a TTY). Returns 0/0 on non-TTYs without error so
// callers can decide whether to skip resize.
func localTerminalSize(stdin io.Reader) (cols, rows uint32, err error) {
	f, ok := stdin.(*os.File)
	if !ok {
		return 0, 0, nil
	}
	fd := int(f.Fd())
	if !term.IsTerminal(fd) {
		return 0, 0, nil
	}
	w, h, err := term.GetSize(fd)
	if err != nil {
		return 0, 0, err
	}
	return uint32(w), uint32(h), nil
}

// watchSIGWINCH installs a SIGWINCH handler that re-queries the
// local terminal size and forwards it to the remote via the control
// client. Runs until ctx is cancelled.
func watchSIGWINCH(ctx context.Context, stdin io.Reader, control *controlClient, logger *slog.Logger) {
	if control == nil {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, unix.SIGWINCH)
	defer signal.Stop(ch)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			cols, rows, err := localTerminalSize(stdin)
			if err != nil || cols == 0 || rows == 0 {
				continue
			}
			if err := control.SendResize(cols, rows); err != nil {
				logger.Warn("forward SIGWINCH", "err", err)
				return
			}
		}
	}
}

// isProtocolNotSupported reports whether err is libp2p's "protocol
// not supported" — used to fall back gracefully when the remote
// doesn't speak /ship/control/.
func isProtocolNotSupported(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "protocol not supported") || strings.Contains(msg, "protocols not supported")
}
