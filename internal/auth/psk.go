package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/encoding/protodelim"

	"github.com/firefly-engineering/ship/internal/api"
)

// HKDF info parameter used when deriving the shared HMAC key from
// the user-supplied secret. Stable across versions; changing it
// would break compat between peers that share the same plaintext
// secret but disagree about derivation.
const pskInfo = "ship.v1.psk"

// MAC binding labels keep the two directions' MACs distinguishable
// so a passive attacker can't replay the server's MAC as the
// client's (or vice versa).
const (
	macLabelServer = "ship-auth-v1:S"
	macLabelClient = "ship-auth-v1:C"
)

// nonceSize is the per-direction challenge length. 32 bytes is well
// above the standard 16 — cheap insurance.
const nonceSize = 32

// NewPSKAuth derives a 32-byte HMAC key from the supplied plaintext
// secret via HKDF-SHA256 (salt = nil, info = "ship.v1.psk").
func NewPSKAuth(secret string) (*PSKAuth, error) {
	if secret == "" {
		return nil, errors.New("ship/auth: PSK secret must be non-empty")
	}
	key, err := derivePSKKey(secret)
	if err != nil {
		return nil, err
	}
	return &PSKAuth{key: key}, nil
}

// PSKAuth is an [Authenticator] backed by a workspace-wide
// pre-shared key. Both peers must derive the same key from the
// same plaintext for the handshake to complete.
type PSKAuth struct {
	key [32]byte
}

// Name implements [Authenticator].
func (a *PSKAuth) Name() string { return "psk" }

// ClientHandshake implements [Authenticator]. Sends ClientHello,
// validates the ServerProof, sends ClientProof.
func (a *PSKAuth) ClientHandshake(_ context.Context, stream io.ReadWriteCloser) error {
	nonceC, err := randomNonce()
	if err != nil {
		return fmt.Errorf("ship/auth(psk): nonce: %w", err)
	}

	if err := writeAuth(stream, &api.AuthMessage{
		Kind: &api.AuthMessage_ClientHello{
			ClientHello: &api.ClientHello{Nonce: nonceC[:]},
		},
	}); err != nil {
		return fmt.Errorf("ship/auth(psk): send client_hello: %w", err)
	}

	var resp api.AuthMessage
	if err := readAuth(stream, &resp); err != nil {
		return fmt.Errorf("ship/auth(psk): read server_proof: %w", err)
	}
	sp := resp.GetServerProof()
	if sp == nil {
		return fmt.Errorf("ship/auth(psk): %w: server sent %T, expected ServerProof", ErrUnauthorized, resp.GetKind())
	}
	nonceS := sp.GetNonce()
	if len(nonceS) != nonceSize {
		return fmt.Errorf("ship/auth(psk): %w: server nonce length %d", ErrUnauthorized, len(nonceS))
	}
	wantServerMac := mac(a.key[:], macLabelServer, nonceC[:], nonceS)
	if subtle.ConstantTimeCompare(sp.GetMac(), wantServerMac) != 1 {
		return fmt.Errorf("ship/auth(psk): %w: server mac mismatch", ErrUnauthorized)
	}

	clientMac := mac(a.key[:], macLabelClient, nonceS, nonceC[:])
	if err := writeAuth(stream, &api.AuthMessage{
		Kind: &api.AuthMessage_ClientProof{
			ClientProof: &api.ClientProof{Mac: clientMac},
		},
	}); err != nil {
		return fmt.Errorf("ship/auth(psk): send client_proof: %w", err)
	}
	return nil
}

// ServerHandshake implements [Authenticator]. Mirror of the client
// path: read ClientHello, send ServerProof, validate ClientProof.
func (a *PSKAuth) ServerHandshake(_ context.Context, stream io.ReadWriteCloser) error {
	var hello api.AuthMessage
	if err := readAuth(stream, &hello); err != nil {
		return fmt.Errorf("ship/auth(psk): read client_hello: %w", err)
	}
	ch := hello.GetClientHello()
	if ch == nil {
		return fmt.Errorf("ship/auth(psk): %w: client sent %T, expected ClientHello", ErrUnauthorized, hello.GetKind())
	}
	nonceC := ch.GetNonce()
	if len(nonceC) != nonceSize {
		return fmt.Errorf("ship/auth(psk): %w: client nonce length %d", ErrUnauthorized, len(nonceC))
	}

	nonceS, err := randomNonce()
	if err != nil {
		return fmt.Errorf("ship/auth(psk): nonce: %w", err)
	}
	serverMac := mac(a.key[:], macLabelServer, nonceC, nonceS[:])
	if err := writeAuth(stream, &api.AuthMessage{
		Kind: &api.AuthMessage_ServerProof{
			ServerProof: &api.ServerProof{Nonce: nonceS[:], Mac: serverMac},
		},
	}); err != nil {
		return fmt.Errorf("ship/auth(psk): send server_proof: %w", err)
	}

	var finish api.AuthMessage
	if err := readAuth(stream, &finish); err != nil {
		return fmt.Errorf("ship/auth(psk): read client_proof: %w", err)
	}
	cp := finish.GetClientProof()
	if cp == nil {
		return fmt.Errorf("ship/auth(psk): %w: client sent %T, expected ClientProof", ErrUnauthorized, finish.GetKind())
	}
	wantClientMac := mac(a.key[:], macLabelClient, nonceS[:], nonceC)
	if subtle.ConstantTimeCompare(cp.GetMac(), wantClientMac) != 1 {
		return fmt.Errorf("ship/auth(psk): %w: client mac mismatch", ErrUnauthorized)
	}
	return nil
}

// KeyHex returns the derived HMAC key as hex. Test-only.
func (a *PSKAuth) KeyHex() string { return hex.EncodeToString(a.key[:]) }

// derivePSKKey runs HKDF-SHA256 to expand `secret` into 32 bytes.
func derivePSKKey(secret string) ([32]byte, error) {
	var out [32]byte
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte(pskInfo))
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, fmt.Errorf("ship/auth: derive PSK key: %w", err)
	}
	return out, nil
}

// mac computes HMAC-SHA256(key, label || nonceA || nonceB). The
// label byte-string is folded into the input so a single key can
// safely produce direction-specific tags.
func mac(key []byte, label string, nonceA, nonceB []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	h.Write(nonceA)
	h.Write(nonceB)
	return h.Sum(nil)
}

// randomNonce returns nonceSize random bytes.
func randomNonce() ([nonceSize]byte, error) {
	var n [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, n[:]); err != nil {
		return n, err
	}
	return n, nil
}

// readAuth reads one length-delimited [api.AuthMessage] from r.
func readAuth(r io.Reader, msg *api.AuthMessage) error {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = &singleByteReader{r: r}
	}
	combined := struct {
		io.Reader
		io.ByteReader
	}{Reader: r, ByteReader: br}
	return protodelim.UnmarshalFrom(combined, msg)
}

// writeAuth marshals msg as a length-delimited frame and writes it
// to w.
func writeAuth(w io.Writer, msg *api.AuthMessage) error {
	_, err := protodelim.MarshalTo(w, msg)
	return err
}

// singleByteReader adapts an [io.Reader] to [io.ByteReader].
// protodelim needs a ByteReader to scan the varint length prefix;
// libp2p streams don't bring one natively.
type singleByteReader struct {
	r io.Reader
	b [1]byte
}

func (s *singleByteReader) ReadByte() (byte, error) {
	n, err := io.ReadFull(s.r, s.b[:])
	if err != nil {
		return 0, err
	}
	if n != 1 {
		return 0, io.ErrUnexpectedEOF
	}
	return s.b[0], nil
}
