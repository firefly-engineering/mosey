package vterm_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protodelim"

	"github.com/firefly-engineering/ship/internal/api"
	"github.com/firefly-engineering/ship/internal/auth"
	"github.com/firefly-engineering/ship/internal/transport"
	"github.com/firefly-engineering/ship/internal/vterm"
)

// readControlMessage reads one length-delimited [api.ControlMessage]
// from stream. [protodelim.UnmarshalFrom] needs both an
// [io.Reader] and an [io.ByteReader] — transport.Stream only
// provides the former, so we adapt with a one-byte buffer.
func readControlMessage(stream transport.Stream, msg *api.ControlMessage) error {
	br := &byteReader{r: stream}
	adapter := struct {
		io.Reader
		io.ByteReader
	}{Reader: stream, ByteReader: br}
	return protodelim.UnmarshalFrom(adapter, msg)
}

type byteReader struct {
	r transport.Stream
	b [1]byte
}

func (b *byteReader) ReadByte() (byte, error) {
	if _, err := b.r.Read(b.b[:]); err != nil {
		return 0, err
	}
	return b.b[0], nil
}

func TestListClients_ReturnsAttachedRegistry(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	secrets := []auth.NamedSecret{
		{Label: auth.LabelOwner, Secret: "owner-pw",
			Caps: auth.Capabilities{Owner: true, Write: true, Resize: true}},
		{Label: auth.LabelReader, Secret: "reader-pw",
			Caps: auth.Capabilities{}},
	}
	target, _, cleanup := newVtermSession(t, ctx, vterm.ModeMultiWrite, []string{"cat"}, secrets)
	defer cleanup()

	owner := newAttachClient(t, ctx, target, "owner-pw", auth.LabelOwner,
		auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer owner.Close()
	reader := newAttachClient(t, ctx, target, "reader-pw", auth.LabelReader,
		auth.Capabilities{})
	defer reader.Close()
	time.Sleep(300 * time.Millisecond)

	ctrl, err := owner.authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("ctrl dial: %v", err)
	}
	defer func() { _ = ctrl.Close() }()

	if _, err := protodelim.MarshalTo(ctrl, &api.ControlMessage{
		Payload: &api.ControlMessage_ListClients{ListClients: &api.ListClients{}},
	}); err != nil {
		t.Fatalf("send list_clients: %v", err)
	}

	var resp api.ControlMessage
	if err := readControlMessage(ctrl, &resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	list := resp.GetClientList()
	if list == nil {
		t.Fatalf("expected ClientList, got %T", resp.GetPayload())
	}
	if len(list.GetClients()) != 2 {
		t.Fatalf("expected 2 clients, got %d: %+v", len(list.GetClients()), list.GetClients())
	}

	labels := map[string]bool{}
	canWrite := map[string]bool{}
	for _, c := range list.GetClients() {
		labels[c.GetLabel()] = true
		canWrite[c.GetLabel()] = c.GetCanWrite()
	}
	if !labels[auth.LabelOwner] || !labels[auth.LabelReader] {
		t.Errorf("missing expected labels; got %+v", labels)
	}
	if !canWrite[auth.LabelOwner] {
		t.Errorf("owner should have can_write=true")
	}
	if canWrite[auth.LabelReader] {
		t.Errorf("reader should have can_write=false")
	}
}

func TestPromote_OwnerCanFlipReaderWritePermission(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	secrets := []auth.NamedSecret{
		{Label: auth.LabelOwner, Secret: "owner-pw",
			Caps: auth.Capabilities{Owner: true, Write: true, Resize: true}},
		{Label: auth.LabelReader, Secret: "reader-pw",
			Caps: auth.Capabilities{}},
	}
	target, _, cleanup := newVtermSession(t, ctx, vterm.ModeMultiWrite, []string{"cat"}, secrets)
	defer cleanup()

	owner := newAttachClient(t, ctx, target, "owner-pw", auth.LabelOwner,
		auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer owner.Close()
	reader := newAttachClient(t, ctx, target, "reader-pw", auth.LabelReader,
		auth.Capabilities{})
	defer reader.Close()
	time.Sleep(300 * time.Millisecond)

	// Sanity: reader's writes get dropped pre-promotion.
	if _, err := reader.stdinW.Write([]byte("pre-promote\n")); err != nil {
		t.Fatalf("reader write: %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	if strings.Contains(owner.out.String()+reader.out.String(), "pre-promote") {
		t.Fatal("reader's input went through before promotion")
	}

	// Owner lists clients → picks reader's id → promotes.
	ctrl, err := owner.authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("ctrl dial: %v", err)
	}
	defer func() { _ = ctrl.Close() }()

	_, _ = protodelim.MarshalTo(ctrl, &api.ControlMessage{
		Payload: &api.ControlMessage_ListClients{ListClients: &api.ListClients{}},
	})
	var resp api.ControlMessage
	if err := readControlMessage(ctrl, &resp); err != nil {
		t.Fatalf("list response: %v", err)
	}
	var readerID int64
	for _, c := range resp.GetClientList().GetClients() {
		if c.GetLabel() == auth.LabelReader {
			readerID = c.GetClientId()
			break
		}
	}
	if readerID == 0 {
		t.Fatal("reader not in list")
	}

	_, _ = protodelim.MarshalTo(ctrl, &api.ControlMessage{
		Payload: &api.ControlMessage_Promote{Promote: &api.Promote{ClientId: readerID}},
	})
	time.Sleep(200 * time.Millisecond)

	// Reader's writes should now reach the PTY.
	if _, err := reader.stdinW.Write([]byte("post-promote\n")); err != nil {
		t.Fatalf("reader write 2: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(owner.out.String()+reader.out.String(), "post-promote") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("reader's post-promote input never reached PTY; owner=%q reader=%q", owner.out.String(), reader.out.String())
}

func TestKick_OwnerCanDisconnectClient(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	target, _, cleanup := newVtermSession(t, ctx, vterm.ModeMultiWrite, []string{"cat"}, ownerSecrets)
	defer cleanup()

	owner := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner,
		auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer owner.Close()
	victim := newAttachClient(t, ctx, target, testSecret, auth.LabelOwner,
		auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer victim.Close()
	time.Sleep(300 * time.Millisecond)

	ctrl, err := owner.authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("ctrl dial: %v", err)
	}
	defer func() { _ = ctrl.Close() }()

	_, _ = protodelim.MarshalTo(ctrl, &api.ControlMessage{
		Payload: &api.ControlMessage_ListClients{ListClients: &api.ListClients{}},
	})
	var resp api.ControlMessage
	if err := readControlMessage(ctrl, &resp); err != nil {
		t.Fatalf("list response: %v", err)
	}
	if len(resp.GetClientList().GetClients()) != 2 {
		t.Fatalf("expected 2 clients before kick, got %d", len(resp.GetClientList().GetClients()))
	}

	// We don't know which id is "owner" vs "victim" — kick whichever
	// has a higher id (most recent = victim per ordering of
	// newAttachClient calls).
	var victimID int64
	for _, c := range resp.GetClientList().GetClients() {
		if c.GetClientId() > victimID {
			victimID = c.GetClientId()
		}
	}

	_, _ = protodelim.MarshalTo(ctrl, &api.ControlMessage{
		Payload: &api.ControlMessage_Kick{Kick: &api.Kick{ClientId: victimID}},
	})

	// Victim should exit.
	select {
	case <-victim.done:
	case <-time.After(3 * time.Second):
		t.Fatal("kicked client did not exit within 3s")
	}

	// Owner is still in the list.
	_, _ = protodelim.MarshalTo(ctrl, &api.ControlMessage{
		Payload: &api.ControlMessage_ListClients{ListClients: &api.ListClients{}},
	})
	resp.Reset()
	if err := readControlMessage(ctrl, &resp); err != nil {
		t.Fatalf("post-kick list response: %v", err)
	}
	if got := len(resp.GetClientList().GetClients()); got != 1 {
		t.Errorf("expected 1 client after kick, got %d", got)
	}
}

func TestKick_NonOwnerDenied(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	secrets := []auth.NamedSecret{
		{Label: auth.LabelOwner, Secret: "owner-pw",
			Caps: auth.Capabilities{Owner: true, Write: true, Resize: true}},
		{Label: auth.LabelReader, Secret: "reader-pw",
			Caps: auth.Capabilities{}},
	}
	target, _, cleanup := newVtermSession(t, ctx, vterm.ModeMultiWrite, []string{"cat"}, secrets)
	defer cleanup()

	owner := newAttachClient(t, ctx, target, "owner-pw", auth.LabelOwner,
		auth.Capabilities{Owner: true, Write: true, Resize: true})
	defer owner.Close()
	reader := newAttachClient(t, ctx, target, "reader-pw", auth.LabelReader,
		auth.Capabilities{})
	defer reader.Close()
	time.Sleep(300 * time.Millisecond)

	ctrl, err := reader.authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		t.Fatalf("reader ctrl: %v", err)
	}
	defer func() { _ = ctrl.Close() }()

	// Reader gets list (everyone can list).
	_, _ = protodelim.MarshalTo(ctrl, &api.ControlMessage{
		Payload: &api.ControlMessage_ListClients{ListClients: &api.ListClients{}},
	})
	var resp api.ControlMessage
	if err := readControlMessage(ctrl, &resp); err != nil {
		t.Fatalf("list response: %v", err)
	}
	var ownerID int64
	for _, c := range resp.GetClientList().GetClients() {
		if c.GetLabel() == auth.LabelOwner {
			ownerID = c.GetClientId()
			break
		}
	}
	if ownerID == 0 {
		t.Fatal("owner not in list")
	}

	// Reader attempts to kick the owner — should be silently ignored.
	_, _ = protodelim.MarshalTo(ctrl, &api.ControlMessage{
		Payload: &api.ControlMessage_Kick{Kick: &api.Kick{ClientId: ownerID}},
	})
	time.Sleep(300 * time.Millisecond)

	// Owner should still be alive.
	select {
	case <-owner.done:
		t.Fatal("non-owner managed to kick the owner")
	default:
	}
}
