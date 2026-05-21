package vterm_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"google.golang.org/protobuf/encoding/protodelim"

	"github.com/firefly-engineering/ship/internal/api"
	"github.com/firefly-engineering/ship/internal/auth"
	libp2pbackend "github.com/firefly-engineering/ship/internal/transport/libp2p"
	"github.com/firefly-engineering/ship/internal/vterm"
)

// TestVterm_ResizeAppliesViaControlStream stands up a vterm running
// a tiny shell loop that prints the terminal size on every SIGWINCH
// (via `trap` + `stty size`), connects an attacher, opens the
// control stream, sends a Resize, and asserts the new size appears
// in the PTY output. End-to-end exercise of /ship/control/1.0.0 +
// the daemon-side TIOCSWINSZ wiring.
func TestVterm_ResizeAppliesViaControlStream(t *testing.T) {
	t.Parallel()

	psk, err := auth.NewPSKAuth("test-secret")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	vtermHost, err := libp2pbackend.New(ctx, libp2pbackend.Options{
		Auth:      psk,
		Bootstrap: []peer.AddrInfo{},
	})
	if err != nil {
		t.Fatalf("vterm host: %v", err)
	}
	defer func() { _ = vtermHost.Close() }()

	// On WINCH, print "WINCH:<rows>x<cols>". The first stty before
	// the trap loop prints the initial size; useful for verifying
	// the default (80x24) and the post-Resize size.
	script := "stty size; trap 'stty size' WINCH; while true; do sleep 0.1; done"
	vtermDone := make(chan error, 1)
	go func() {
		vtermDone <- vterm.Run(ctx, vterm.Options{Host: vtermHost.Host()}, []string{"bash", "-c", script})
	}()

	// Let vterm.Run register handlers + spawn the child.
	time.Sleep(300 * time.Millisecond)

	attachHost, err := libp2pbackend.New(ctx, libp2pbackend.Options{
		Auth:      psk,
		Bootstrap: []peer.AddrInfo{},
	})
	if err != nil {
		t.Fatalf("attach host: %v", err)
	}
	defer func() { _ = attachHost.Close() }()

	target := peer.AddrInfo{ID: vtermHost.Host().ID(), Addrs: vtermHost.Host().Addrs()}
	if err := attachHost.Host().Connect(ctx, target); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Open the PTY stream first so we can read output continuously.
	ptyStream, err := attachHost.Host().NewStream(ctx, target.ID, api.ProtoPTY)
	if err != nil {
		t.Fatalf("open pty stream: %v", err)
	}
	defer func() { _ = ptyStream.Reset() }()

	// Read PTY output into a syncBuffer (defined in integration_test.go).
	output := &syncBuffer{}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptyStream.Read(buf)
			if n > 0 {
				_, _ = output.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for the initial stty output to appear. With our 80x24
	// default that's "24 80".
	if !waitForString(output, "24 80", 5*time.Second) {
		t.Fatalf("initial stty size never appeared; got: %q", output.String())
	}

	// Open the control stream and send a Resize to 40x120.
	ctrl, err := attachHost.Host().NewStream(ctx, target.ID, protocol.ID(api.ProtoControl))
	if err != nil {
		t.Fatalf("open control stream: %v", err)
	}
	defer func() { _ = ctrl.Reset() }()

	resize := &api.ControlMessage{
		Payload: &api.ControlMessage_Resize{
			Resize: &api.Resize{Cols: 120, Rows: 40},
		},
	}
	if _, err := protodelim.MarshalTo(ctrl, resize); err != nil {
		t.Fatalf("send resize: %v", err)
	}

	// stty size after WINCH prints "40 120".
	if !waitForString(output, "40 120", 5*time.Second) {
		t.Fatalf("post-resize stty never appeared; got: %q", output.String())
	}
}

// waitForString polls buf until it contains needle, returning true
// on hit and false on timeout.
func waitForString(buf *syncBuffer, needle string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), needle) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
