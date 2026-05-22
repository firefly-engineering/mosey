package vterm_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protodelim"

	"github.com/firefly-engineering/mosey/api"
	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/vterm"
)

// TestGeometry_MinAcrossClients confirms that in a multi-client
// mode the PTY's effective size is min(cols) × min(rows) across
// every reporting client. Uses a bash trap on WINCH to surface
// the live size via stty.
func TestGeometry_MinAcrossClients(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	script := "stty size; trap 'stty size' WINCH; while true; do sleep 0.1; done"
	target, _, cleanup := newVtermSession(t, ctx, vterm.ModeMultiWrite, []string{"bash", "-c", script}, ownerSecrets)
	defer cleanup()

	// Client A: opens PTY + control, advertises 100 cols × 40 rows.
	a := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer a.Close()
	// Wait for A's attach to register on the vterm side. Initial
	// PTY size is 80×24 so bash's first stty prints "24 80".
	if !waitForString(a.out, "24 80", 5*time.Second) {
		t.Fatalf("A never observed initial stty size; out=%q", a.out.String())
	}
	ctrlA, err := a.authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("ctrlA dial: %v", err)
	}
	defer func() { _ = ctrlA.Close() }()
	if _, err := protodelim.MarshalTo(ctrlA, &api.ControlMessage{
		Payload: &api.ControlMessage_Resize{Resize: &api.Resize{Cols: 100, Rows: 40}},
	}); err != nil {
		t.Fatalf("send resize A: %v", err)
	}

	// Wait for A's size to land — bash should print "40 100".
	if !waitForString(a.out, "40 100", 5*time.Second) {
		t.Fatalf("A's size never landed; got %q", a.out.String())
	}

	// Client B: 60 cols × 30 rows (smaller in both dimensions).
	b := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer b.Close()
	ctrlB, err := b.authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("ctrlB dial: %v", err)
	}
	defer func() { _ = ctrlB.Close() }()
	// Give B's PTY attach + its initial replay a moment to land
	// before sending Resize so the WINCH redraws don't race.
	time.Sleep(200 * time.Millisecond)
	if _, err := protodelim.MarshalTo(ctrlB, &api.ControlMessage{
		Payload: &api.ControlMessage_Resize{Resize: &api.Resize{Cols: 60, Rows: 30}},
	}); err != nil {
		t.Fatalf("send resize B: %v", err)
	}

	// After B's resize the PTY size should fall to min: 30×60.
	if !waitForString(a.out, "30 60", 5*time.Second) {
		t.Fatalf("min-geometry redraw never appeared; A output:\n%s", a.out.String())
	}
}

// TestGeometry_DepartingClientGrowsPTY: when the size-constraining
// client leaves, the PTY size grows back to match the remaining
// clients. Reverse of the min-computation case.
func TestGeometry_DepartingClientGrowsPTY(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	script := "stty size; trap 'stty size' WINCH; while true; do sleep 0.1; done"
	target, _, cleanup := newVtermSession(t, ctx, vterm.ModeMultiWrite, []string{"bash", "-c", script}, ownerSecrets)
	defer cleanup()

	a := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer a.Close()
	if !waitForString(a.out, "24 80", 5*time.Second) {
		t.Fatalf("A never observed initial stty size; out=%q", a.out.String())
	}
	ctrlA, err := a.authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("ctrlA: %v", err)
	}
	_, _ = protodelim.MarshalTo(ctrlA, &api.ControlMessage{
		Payload: &api.ControlMessage_Resize{Resize: &api.Resize{Cols: 120, Rows: 50}},
	})
	_ = ctrlA.Close()

	// Wait for A's geometry to land first so we know the initial
	// state, then attach B which will narrow the PTY.
	if !waitForString(a.out, "50 120", 5*time.Second) {
		t.Fatalf("A's initial geometry never landed; out=%q", a.out.String())
	}

	b := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner, auth.Capabilities{Owner: true, Write: true, Resize: true})
	// Wait for B's attach to land — replay buffer should immediately
	// dump A's "50 120" into B's output, so we use that as our
	// "B is attached" signal.
	if !waitForString(b.out, "50 120", 5*time.Second) {
		t.Fatalf("B never received initial replay; out=%q", b.out.String())
	}
	ctrlB, err := b.authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("ctrlB: %v", err)
	}
	_, _ = protodelim.MarshalTo(ctrlB, &api.ControlMessage{
		Payload: &api.ControlMessage_Resize{Resize: &api.Resize{Cols: 40, Rows: 20}},
	})
	_ = ctrlB.Close()
	if !waitForString(a.out, "20 40", 5*time.Second) {
		t.Fatalf("min geometry after B joined never landed; out=%q", a.out.String())
	}

	// B disconnects. Min reverts to A's 120×50.
	mark := len(a.out.String())
	b.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		tail := a.out.String()[mark:]
		if strings.Contains(tail, "50 120") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("PTY did not grow back to A's geometry after B left; A tail=%q", a.out.String()[mark:])
}
