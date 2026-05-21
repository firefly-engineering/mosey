package vterm_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/firefly-engineering/mosey/internal/attach"
	"github.com/firefly-engineering/mosey/internal/auth"
	libp2pbackend "github.com/firefly-engineering/mosey/internal/transport/libp2p"
	"github.com/firefly-engineering/mosey/internal/vterm"
)

// TestVterm_ReaderSecretIsObserverOnly stands up a vterm with both
// owner + reader secrets configured, attaches with the reader
// secret, sends input bytes, and asserts they don't appear in the
// PTY's output stream. Compare with the owner-secret control: a
// follow-up attach with the owner credential sees its own input
// echoed back.
func TestVterm_ReaderSecretIsObserverOnly(t *testing.T) {
	t.Parallel()

	const ownerSecret = "owner-pw"
	const readerSecret = "reader-pw"

	serverAuth, err := auth.NewMultiPSKAuth([]auth.NamedSecret{
		{Label: auth.LabelOwner, Secret: ownerSecret, Caps: auth.Capabilities{Owner: true, Write: true, Resize: true}},
		{Label: auth.LabelReader, Secret: readerSecret, Caps: auth.Capabilities{}},
	})
	if err != nil {
		t.Fatalf("server auth: %v", err)
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
	vtermAuthed := auth.Wrap(vtermBackend, serverAuth)
	vtermAuthed.Serve()

	vtermDone := make(chan error, 1)
	go func() {
		vtermDone <- vterm.Run(ctx, vterm.Options{Transport: vtermAuthed}, []string{"cat"})
	}()
	time.Sleep(100 * time.Millisecond)

	endpoints := vtermBackend.Endpoints()
	if len(endpoints) == 0 {
		t.Fatal("vterm host published no endpoints")
	}
	target := endpoints[0]

	// Reader-side attach: send "do-not-echo\n"; cat shouldn't echo
	// it back because the vterm drops reader input.
	readerAuth, _ := auth.NewMultiPSKAuth([]auth.NamedSecret{{
		Label:  auth.LabelReader,
		Secret: readerSecret,
		Caps:   auth.Capabilities{},
	}})
	readerBackend, err := libp2pbackend.New(ctx, libp2pbackend.Options{
		Bootstrap: []peer.AddrInfo{},
	})
	if err != nil {
		t.Fatalf("reader host: %v", err)
	}
	defer func() { _ = readerBackend.Close() }()
	readerAuthed := auth.Wrap(readerBackend, readerAuth)

	readerStdinR, readerStdinW := io.Pipe()
	defer readerStdinR.Close()
	defer readerStdinW.Close()
	readerOut := &syncBuffer{}
	readerDone := make(chan error, 1)
	go func() {
		readerDone <- attach.Run(ctx, attach.Options{
			Transport: readerAuthed,
			Target:    target,
			Stdin:     readerStdinR,
			Stdout:    readerOut,
		})
	}()
	time.Sleep(150 * time.Millisecond)
	if _, err := readerStdinW.Write([]byte("do-not-echo\n")); err != nil {
		t.Fatalf("write reader stdin: %v", err)
	}

	// Owner-side attach: send "yes-echo\n"; this one SHOULD appear
	// in both attach sessions' stdout (PTY broadcast races aside,
	// at least the writer sees it).
	ownerAuth, _ := auth.NewMultiPSKAuth([]auth.NamedSecret{{
		Label:  auth.LabelOwner,
		Secret: ownerSecret,
		Caps:   auth.Capabilities{Owner: true, Write: true, Resize: true},
	}})
	ownerBackend, err := libp2pbackend.New(ctx, libp2pbackend.Options{
		Bootstrap: []peer.AddrInfo{},
	})
	if err != nil {
		t.Fatalf("owner host: %v", err)
	}
	defer func() { _ = ownerBackend.Close() }()
	ownerAuthed := auth.Wrap(ownerBackend, ownerAuth)

	ownerStdinR, ownerStdinW := io.Pipe()
	defer ownerStdinR.Close()
	defer ownerStdinW.Close()
	ownerOut := &syncBuffer{}
	ownerDone := make(chan error, 1)
	go func() {
		ownerDone <- attach.Run(ctx, attach.Options{
			Transport: ownerAuthed,
			Target:    target,
			Stdin:     ownerStdinR,
			Stdout:    ownerOut,
		})
	}()
	time.Sleep(150 * time.Millisecond)
	if _, err := ownerStdinW.Write([]byte("yes-echo\n")); err != nil {
		t.Fatalf("write owner stdin: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(ownerOut.String()+readerOut.String(), "yes-echo") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	combined := ownerOut.String() + readerOut.String()
	if strings.Contains(combined, "do-not-echo") {
		t.Errorf("reader's input made it through; PTY output contained %q (combined output: %q)", "do-not-echo", combined)
	}
	if !strings.Contains(combined, "yes-echo") {
		t.Errorf("owner's input did not appear in either attach session; output:\n  owner=%q\n  reader=%q", ownerOut.String(), readerOut.String())
	}

	cancel()
	select {
	case <-ownerDone:
	case <-time.After(2 * time.Second):
		t.Error("owner attach.Run did not return within 2s of cancel")
	}
	select {
	case <-readerDone:
	case <-time.After(2 * time.Second):
		t.Error("reader attach.Run did not return within 2s of cancel")
	}
	select {
	case <-vtermDone:
	case <-time.After(2 * time.Second):
		t.Error("vterm.Run did not return within 2s of cancel")
	}
}
