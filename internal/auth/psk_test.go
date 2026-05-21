package auth_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/firefly-engineering/mosey/internal/auth"
)

func TestNewPSKAuth_RejectsEmptySecret(t *testing.T) {
	t.Parallel()
	if _, err := auth.NewPSKAuth(""); err == nil {
		t.Fatal("empty secret must error")
	}
}

func TestPSKAuth_NameIsStable(t *testing.T) {
	t.Parallel()
	a, _ := auth.NewPSKAuth("hunter2")
	if got := a.Name(); got != "psk" {
		t.Errorf("Name = %q, want psk", got)
	}
}

func TestPSKAuth_SameSecretSameKey(t *testing.T) {
	t.Parallel()
	a1, _ := auth.NewPSKAuth("hunter2")
	a2, _ := auth.NewPSKAuth("hunter2")
	if a1.KeyHex() != a2.KeyHex() {
		t.Errorf("identical secrets produced different keys")
	}
}

func TestPSKAuth_DifferentSecretsDifferentKeys(t *testing.T) {
	t.Parallel()
	a1, _ := auth.NewPSKAuth("hunter2")
	a2, _ := auth.NewPSKAuth("hunter3")
	if a1.KeyHex() == a2.KeyHex() {
		t.Errorf("different secrets produced same key")
	}
}

func TestPSKAuth_KeyHexIsHex(t *testing.T) {
	t.Parallel()
	a, _ := auth.NewPSKAuth("hunter2")
	hex := a.KeyHex()
	if len(hex) != 64 {
		t.Errorf("KeyHex length = %d, want 64", len(hex))
	}
	if strings.IndexFunc(hex, func(r rune) bool {
		return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'))
	}) >= 0 {
		t.Errorf("KeyHex contains non-hex chars: %s", hex)
	}
}

// pipePair returns two halves of an in-memory bidi pipe. Reads on
// one half see writes from the other; closing either end propagates.
// Used to drive the auth handshakes in-process.
type pipePair struct {
	clientReader io.PipeReader
	clientWriter io.PipeWriter
	serverReader io.PipeReader
	serverWriter io.PipeWriter
}

// rwc is an io.ReadWriteCloser composed of a separate Reader and
// Writer, closing both on Close.
type rwc struct {
	io.Reader
	io.Writer
	closers []io.Closer
}

func (r *rwc) Close() error {
	for _, c := range r.closers {
		_ = c.Close()
	}
	return nil
}

func newPipeRWC() (client, server io.ReadWriteCloser) {
	c2sR, c2sW := io.Pipe() // client → server
	s2cR, s2cW := io.Pipe() // server → client
	client = &rwc{Reader: s2cR, Writer: c2sW, closers: []io.Closer{c2sW, s2cR}}
	server = &rwc{Reader: c2sR, Writer: s2cW, closers: []io.Closer{s2cW, c2sR}}
	return client, server
}

func TestPSKAuth_Handshake_Succeeds(t *testing.T) {
	t.Parallel()
	a, err := auth.NewPSKAuth("hunter2")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}
	clientSide, serverSide := newPipeRWC()

	type clientResult struct {
		id  auth.Identity
		err error
	}
	clientCh := make(chan clientResult, 1)
	go func() {
		id, err := a.ClientHandshake(context.Background(), clientSide)
		clientCh <- clientResult{id: id, err: err}
	}()

	serverID, err := a.ServerHandshake(context.Background(), serverSide)
	if err != nil {
		t.Fatalf("ServerHandshake: %v", err)
	}
	cr := <-clientCh
	if cr.err != nil {
		t.Fatalf("ClientHandshake: %v", cr.err)
	}
	if !serverID.IsOwner() || !cr.id.IsOwner() {
		t.Errorf("single-secret PSK should yield Owner on both sides; got server=%+v client=%+v", serverID, cr.id)
	}
}

func TestPSKAuth_Handshake_MismatchedSecretsFail(t *testing.T) {
	t.Parallel()
	good, _ := auth.NewPSKAuth("hunter2")
	bad, _ := auth.NewPSKAuth("not-hunter2")
	clientSide, serverSide := newPipeRWC()

	clientErr := make(chan error, 1)
	go func() {
		_, err := good.ClientHandshake(context.Background(), clientSide)
		_ = clientSide.Close()
		clientErr <- err
	}()
	_, serverErr := bad.ServerHandshake(context.Background(), serverSide)
	_ = serverSide.Close()
	cErr := <-clientErr
	if serverErr == nil && cErr == nil {
		t.Fatal("mismatched secrets must fail handshake on at least one side")
	}
	matched := errors.Is(serverErr, auth.ErrUnauthorized) || errors.Is(cErr, auth.ErrUnauthorized)
	if !matched {
		t.Errorf("expected ErrUnauthorized; got serverErr=%v clientErr=%v", serverErr, cErr)
	}
}

func TestMultiPSKAuth_OwnerAndReaderRoles(t *testing.T) {
	t.Parallel()

	// Server side knows both secrets, each mapped to a different
	// Identity. Clients hold one secret each.
	server, err := auth.NewMultiPSKAuth([]auth.NamedSecret{
		{Label: auth.LabelOwner, Secret: "ownerpw", Caps: auth.Capabilities{Owner: true, Write: true, Resize: true}},
		{Label: auth.LabelReader, Secret: "readerpw", Caps: auth.Capabilities{}},
	})
	if err != nil {
		t.Fatalf("NewMultiPSKAuth: %v", err)
	}

	ownerClient, _ := auth.NewMultiPSKAuth([]auth.NamedSecret{
		{Label: auth.LabelOwner, Secret: "ownerpw", Caps: auth.Capabilities{Owner: true, Write: true, Resize: true}},
	})
	readerClient, _ := auth.NewMultiPSKAuth([]auth.NamedSecret{
		{Label: auth.LabelReader, Secret: "readerpw", Caps: auth.Capabilities{}},
	})

	cases := []struct {
		name      string
		client    *auth.PSKAuth
		wantOwner bool
		wantWrite bool
		wantLabel string
	}{
		{"owner role", ownerClient, true, true, auth.LabelOwner},
		{"reader role", readerClient, false, false, auth.LabelReader},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clientSide, serverSide := newPipeRWC()

			type result struct {
				id  auth.Identity
				err error
			}
			ch := make(chan result, 1)
			go func() {
				id, err := tc.client.ClientHandshake(context.Background(), clientSide)
				ch <- result{id: id, err: err}
			}()
			sid, serr := server.ServerHandshake(context.Background(), serverSide)
			if serr != nil {
				t.Fatalf("ServerHandshake: %v", serr)
			}
			cr := <-ch
			if cr.err != nil {
				t.Fatalf("ClientHandshake: %v", cr.err)
			}
			if sid.IsOwner() != tc.wantOwner {
				t.Errorf("server identity IsOwner = %v, want %v", sid.IsOwner(), tc.wantOwner)
			}
			if sid.CanWrite() != tc.wantWrite {
				t.Errorf("server identity CanWrite = %v, want %v", sid.CanWrite(), tc.wantWrite)
			}
			if sid.Label != tc.wantLabel {
				t.Errorf("server identity Label = %q, want %q", sid.Label, tc.wantLabel)
			}
			if cr.id.Label != tc.wantLabel {
				t.Errorf("client identity Label = %q, want %q", cr.id.Label, tc.wantLabel)
			}
		})
	}
}

func TestMultiPSKAuth_WrongSecretForLabelFails(t *testing.T) {
	t.Parallel()

	server, _ := auth.NewMultiPSKAuth([]auth.NamedSecret{
		{Label: auth.LabelOwner, Secret: "ownerpw", Caps: auth.Capabilities{Owner: true}},
		{Label: auth.LabelReader, Secret: "readerpw", Caps: auth.Capabilities{}},
	})

	// Client claims owner role but holds the wrong secret. Should
	// fail because the server's MAC won't validate against the
	// client's key.
	imposter, _ := auth.NewMultiPSKAuth([]auth.NamedSecret{
		{Label: auth.LabelOwner, Secret: "wrong-owner-pw", Caps: auth.Capabilities{Owner: true}},
	})

	clientSide, serverSide := newPipeRWC()
	clientErrCh := make(chan error, 1)
	go func() {
		_, err := imposter.ClientHandshake(context.Background(), clientSide)
		_ = clientSide.Close()
		clientErrCh <- err
	}()
	_, serverErr := server.ServerHandshake(context.Background(), serverSide)
	_ = serverSide.Close()
	clientErr := <-clientErrCh

	if serverErr == nil && clientErr == nil {
		t.Fatal("wrong secret must fail handshake")
	}
	if !errors.Is(serverErr, auth.ErrUnauthorized) && !errors.Is(clientErr, auth.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized; got serverErr=%v clientErr=%v", serverErr, clientErr)
	}
}

func TestMultiPSKAuth_UnknownLabelFails(t *testing.T) {
	t.Parallel()

	server, _ := auth.NewMultiPSKAuth([]auth.NamedSecret{
		{Label: auth.LabelOwner, Secret: "ownerpw", Caps: auth.Capabilities{Owner: true}},
	})

	// Client uses a label the server doesn't know.
	stranger, _ := auth.NewMultiPSKAuth([]auth.NamedSecret{
		{Label: "ghost", Secret: "anything", Caps: auth.Capabilities{}},
	})

	clientSide, serverSide := newPipeRWC()
	go func() {
		_, _ = stranger.ClientHandshake(context.Background(), clientSide)
		_ = clientSide.Close()
	}()
	_, err := server.ServerHandshake(context.Background(), serverSide)
	_ = serverSide.Close()
	if err == nil {
		t.Fatal("server must reject unknown label")
	}
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized; got %v", err)
	}
}

func TestPSKAuth_Handshake_RejectsGarbledServerProof(t *testing.T) {
	t.Parallel()
	a, _ := auth.NewPSKAuth("hunter2")

	// Pre-seed the client's read side with a length-prefixed
	// payload that decodes as garbage (varint says 8 bytes, payload
	// is 0xff repeated — not a valid AuthMessage). The client must
	// detect the decode failure and return an error.
	garbage := append([]byte{0x08}, bytes.Repeat([]byte{0xff}, 8)...)
	clientSide := &rwc{
		Reader: bytes.NewReader(garbage),
		Writer: io.Discard,
	}

	_, err := a.ClientHandshake(context.Background(), clientSide)
	if err == nil {
		t.Fatal("client must reject garbled server proof")
	}
}
