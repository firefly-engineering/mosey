package vterm_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/encoding/protodelim"

	"github.com/firefly-engineering/mosey/api"
	"github.com/firefly-engineering/mosey/auth"
	libp2pbackend "github.com/firefly-engineering/mosey/transport/libp2p"
	"github.com/firefly-engineering/mosey/vterm"
)

// TestVterm_ResizeAppliesViaControlStream stands up a vterm running
// a tiny shell loop that prints the terminal size on every SIGWINCH
// (via `trap` + `stty size`), connects an attacher, opens the
// control stream, sends a Resize, and asserts the new size appears
// in the PTY output. End-to-end exercise of /mosey/control/1.0.0 +
// the daemon-side TIOCSWINSZ wiring.
func TestVterm_ResizeAppliesViaControlStream(t *testing.T) {
	t.Parallel()

	psk, err := auth.NewPSKAuth("test-secret")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	vtermBackend, err := libp2pbackend.New(ctx, libp2pbackend.Options{
		Bootstrap: []peer.AddrInfo{},
	})
	if err != nil {
		t.Fatalf("vterm host: %v", err)
	}
	defer func() { _ = vtermBackend.Close() }()
	vtermAuthed := auth.Wrap(vtermBackend, psk)
	vtermAuthed.Serve()

	script := "stty size; trap 'stty size' WINCH; while true; do sleep 0.1; done"
	vtermDone := make(chan error, 1)
	go func() {
		vtermDone <- vterm.Run(ctx, vterm.Options{Transport: vtermAuthed}, []string{"bash", "-c", script})
	}()

	time.Sleep(300 * time.Millisecond)

	attachBackend, err := libp2pbackend.New(ctx, libp2pbackend.Options{
		Bootstrap: []peer.AddrInfo{},
	})
	if err != nil {
		t.Fatalf("attach host: %v", err)
	}
	defer func() { _ = attachBackend.Close() }()
	attachAuthed := auth.Wrap(attachBackend, psk)

	endpoints := vtermAuthed.Endpoints()
	if len(endpoints) == 0 {
		t.Fatal("vterm host published no endpoints")
	}
	target := endpoints[0]

	ptyStream, err := attachAuthed.Dial(ctx, target, api.ProtoPTY)
	if err != nil {
		t.Fatalf("open pty stream: %v", err)
	}
	defer func() { _ = ptyStream.Close() }()

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

	if !waitForString(output, "24 80", 5*time.Second) {
		t.Fatalf("initial stty size never appeared; got: %q", output.String())
	}

	ctrl, err := attachAuthed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("open control stream: %v", err)
	}
	defer func() { _ = ctrl.Close() }()

	resize := &api.ControlMessage{
		Payload: &api.ControlMessage_Resize{
			Resize: &api.Resize{Cols: 120, Rows: 40},
		},
	}
	if _, err := protodelim.MarshalTo(ctrl, resize); err != nil {
		t.Fatalf("send resize: %v", err)
	}

	if !waitForString(output, "40 120", 5*time.Second) {
		t.Fatalf("post-resize stty never appeared; got: %q", output.String())
	}
}

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
