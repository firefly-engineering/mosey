package vterm_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protodelim"

	"github.com/firefly-engineering/mosey/internal/api"
	"github.com/firefly-engineering/mosey/internal/auth"
	"github.com/firefly-engineering/mosey/internal/vterm"
)

// TestSetMode_OwnerOnly: SetMode from an owner-cap client changes
// the session mode; from a reader-cap client, it's silently
// ignored.
func TestSetMode_OwnerOnly(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	secrets := []auth.NamedSecret{
		{Label: auth.LabelOwner, Secret: "owner-pw",
			Caps: auth.Capabilities{Owner: true, Write: true, Resize: true}},
		{Label: auth.LabelReader, Secret: "reader-pw",
			Caps: auth.Capabilities{}},
	}
	target, _, cleanup := newVtermSession(t, ctx, vterm.ModeSupersede, []string{"cat"}, secrets)
	defer cleanup()

	// Attach as reader first, try to switch mode → should be
	// ignored. Then attach as owner, switch → should succeed.
	reader := newAttachClient(t, ctx, target, "reader-pw", auth.LabelReader, auth.Capabilities{})
	defer reader.Close()
	time.Sleep(200 * time.Millisecond)

	readerCtrl, err := reader.authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("reader ctrl dial: %v", err)
	}
	// Reader attempts SetMode → must be ignored (no Owner cap).
	_, _ = protodelim.MarshalTo(readerCtrl, &api.ControlMessage{
		Payload: &api.ControlMessage_SetMode{
			SetMode: &api.SetMode{Kind: api.SetMode_KIND_EXCLUSIVE},
		},
	})
	_ = readerCtrl.Close()
	// Give the server a moment to (not) apply the change.
	time.Sleep(200 * time.Millisecond)

	// Now an owner connects. Since the mode is still Supersede,
	// the reader should be kicked.
	owner := newAttachClient(t, ctx, target, "owner-pw", auth.LabelOwner,
		auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer owner.Close()
	select {
	case <-reader.done:
		// Reader was kicked — confirms the mode never switched to
		// Exclusive (Exclusive would have refused the owner attach
		// instead of kicking the reader).
	case <-time.After(3 * time.Second):
		t.Fatal("reader was not kicked by the new owner attach (was the mode switch wrongly applied?)")
	}

	// Owner switches the mode to Exclusive.
	ownerCtrl, err := owner.authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("owner ctrl dial: %v", err)
	}
	if _, err := protodelim.MarshalTo(ownerCtrl, &api.ControlMessage{
		Payload: &api.ControlMessage_SetMode{
			SetMode: &api.SetMode{Kind: api.SetMode_KIND_EXCLUSIVE},
		},
	}); err != nil {
		t.Fatalf("owner set mode: %v", err)
	}
	_ = ownerCtrl.Close()
	time.Sleep(200 * time.Millisecond)

	// Owner is still attached. A new attempt to attach should be
	// refused (Exclusive). We verify by attempting and confirming
	// the attach.Run exits immediately.
	intruder := newAttachClient(t, ctx, target, "owner-pw", auth.LabelOwner,
		auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer intruder.Close()
	select {
	case <-intruder.done:
		// Intruder refused — Exclusive worked.
	case <-time.After(3 * time.Second):
		t.Fatal("Exclusive mode did not refuse the second attach")
	}
}

// TestDemote_DropsWritePermission: a writer client demotes itself
// mid-session; subsequent input bytes from that client are
// dropped by the vterm.
func TestDemote_DropsWritePermission(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target, _, cleanup := newVtermSession(t, ctx, vterm.ModeSupersede, []string{"cat"}, ownerSecrets)
	defer cleanup()

	c := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner,
		auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer c.Close()
	time.Sleep(150 * time.Millisecond)

	// Send some input, confirm it echoes back.
	if _, err := c.stdinW.Write([]byte("before-demote\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !waitForString(c.out, "before-demote", 3*time.Second) {
		t.Fatalf("pre-demote echo never appeared; out=%q", c.out.String())
	}

	// Demote self.
	ctrl, err := c.authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("ctrl dial: %v", err)
	}
	if _, err := protodelim.MarshalTo(ctrl, &api.ControlMessage{
		Payload: &api.ControlMessage_Demote{Demote: &api.Demote{}},
	}); err != nil {
		t.Fatalf("demote: %v", err)
	}
	_ = ctrl.Close()
	time.Sleep(200 * time.Millisecond)

	// Send another input — vterm should now silently drop it.
	mark := len(c.out.String())
	if _, err := c.stdinW.Write([]byte("after-demote\n")); err != nil {
		t.Fatalf("post-demote write: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if strings.Contains(c.out.String()[mark:], "after-demote") {
		t.Errorf("post-demote input echoed; demoted client should be observer. tail=%q", c.out.String()[mark:])
	}
}
