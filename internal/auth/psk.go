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

	"github.com/firefly-engineering/mosey/internal/api"
)

// HKDF info parameter used when deriving the per-entry HMAC key
// from the plaintext secret. Stable across versions; changing it
// would break compat between peers that share the same plaintext
// secret but disagree about derivation.
const pskInfo = "mosey.v1.psk"

// MAC binding labels keep the two directions' MACs distinguishable
// so a passive attacker can't replay the server's MAC as the
// client's (or vice versa).
const (
	macLabelServer = "mosey-auth-v1:S"
	macLabelClient = "mosey-auth-v1:C"
)

// errPrefixAuth tags errors that aren't PSK-specific (config
// validation in NewMultiPSKAuth, the cross-cutting HKDF derive
// helper). Also shared by wrap.go for the same subsystem boundary.
const errPrefixAuth = "mosey/auth: "

// errPrefixPSK tags errors that are specific to the PSK
// handshake flow itself — distinct from errPrefixAuth so logs
// disambiguate config errors from on-wire failures.
const errPrefixPSK = "mosey/auth(psk): "

// LabelOwner is the conventional label for the all-powers secret
// configured via [NewPSKAuth] / the --secret CLI flag. The server
// treats an empty [api.ClientHello.Label] as a request for this
// label, preserving the historical single-secret experience.
const LabelOwner = "owner"

// LabelReader is the conventional label for an observer-only
// secret configured alongside the owner secret via
// [NewMultiPSKAuth] / the --reader-secret CLI flag. Holders of
// the reader secret get an [Identity] with empty Capabilities —
// they can attach but not write to or resize the PTY.
const LabelReader = "reader"

// nonceSize is the per-direction challenge length. 32 bytes is well
// above the standard 16 — cheap insurance.
const nonceSize = 32

// NamedSecret pairs a plaintext shared secret with the
// [Capabilities] holders of that secret are granted on successful
// handshake. Labels must be unique within a single [PSKAuth].
type NamedSecret struct {
	Label  string
	Secret string
	Caps   Capabilities
}

// NewPSKAuth derives a 32-byte HMAC key from the supplied plaintext
// secret and returns an authenticator that treats every successful
// handshake as Owner. Equivalent to NewMultiPSKAuth with one entry
// labeled [LabelOwner].
func NewPSKAuth(secret string) (*PSKAuth, error) {
	return NewMultiPSKAuth([]NamedSecret{{
		Label:  LabelOwner,
		Secret: secret,
		Caps:   Capabilities{Owner: true, Write: true, Resize: true},
	}})
}

// NewMultiPSKAuth builds a PSKAuth with one entry per supplied
// NamedSecret. Each entry's secret derives its own HMAC key; on the
// server side, the client's [api.ClientHello.Label] picks which
// entry the server verifies against (empty label maps to
// [LabelOwner] when present). On the client side, the FIRST entry
// is sent as the client's label / used for MAC generation —
// typical usage is one entry per client (named with its role).
func NewMultiPSKAuth(entries []NamedSecret) (*PSKAuth, error) {
	if len(entries) == 0 {
		return nil, errors.New(errPrefixAuth + "at least one secret entry required")
	}
	out := &PSKAuth{
		byLabel: make(map[string]entry, len(entries)),
		order:   make([]string, 0, len(entries)),
	}
	for _, ns := range entries {
		if ns.Label == "" {
			return nil, errors.New(errPrefixAuth + "secret entry needs a non-empty Label")
		}
		if ns.Secret == "" {
			return nil, fmt.Errorf(errPrefixAuth+"secret entry %q has empty Secret", ns.Label)
		}
		if _, dup := out.byLabel[ns.Label]; dup {
			return nil, fmt.Errorf(errPrefixAuth+"duplicate label %q", ns.Label)
		}
		key, err := derivePSKKey(ns.Secret)
		if err != nil {
			return nil, err
		}
		out.byLabel[ns.Label] = entry{
			label: ns.Label,
			key:   key,
			identity: Identity{
				Label: ns.Label,
				Caps:  ns.Caps,
			},
		}
		out.order = append(out.order, ns.Label)
	}
	return out, nil
}

// PSKAuth is an [Authenticator] backed by one or more named PSKs.
// Server-side: the client's label hint picks the entry the server
// verifies against; on match, the entry's Identity is returned.
// Client-side: the first registered entry is used for the
// handshake; that entry's label is sent as the [api.ClientHello]
// hint.
type PSKAuth struct {
	byLabel map[string]entry
	order   []string // registration order; client uses order[0]
}

type entry struct {
	label    string
	key      [32]byte
	identity Identity
}

// Name implements [Authenticator].
func (a *PSKAuth) Name() string { return "psk" }

// ClientHandshake implements [Authenticator]. Uses the first
// registered entry; sends its label in ClientHello, computes its
// MAC over the configured key. Single-entry PSKAuths
// (single-secret use) produce the historical "everyone is owner"
// shape.
func (a *PSKAuth) ClientHandshake(_ context.Context, stream io.ReadWriteCloser) (Identity, error) {
	if len(a.order) == 0 {
		return Identity{}, errors.New(errPrefixPSK + "no entries configured")
	}
	clientEntry := a.byLabel[a.order[0]]

	nonceC, err := randomNonce()
	if err != nil {
		return Identity{}, fmt.Errorf(errPrefixPSK+"nonce: %w", err)
	}

	if err := writeAuth(stream, &api.AuthMessage{
		Kind: &api.AuthMessage_ClientHello{
			ClientHello: &api.ClientHello{
				Nonce: nonceC[:],
				Label: clientEntry.label,
			},
		},
	}); err != nil {
		return Identity{}, fmt.Errorf(errPrefixPSK+"send client_hello: %w", err)
	}

	var resp api.AuthMessage
	if err := readAuth(stream, &resp); err != nil {
		return Identity{}, fmt.Errorf(errPrefixPSK+"read server_proof: %w", err)
	}
	sp := resp.GetServerProof()
	if sp == nil {
		return Identity{}, fmt.Errorf(errPrefixPSK+"%w: server sent %T, expected ServerProof", ErrUnauthorized, resp.GetKind())
	}
	nonceS := sp.GetNonce()
	if len(nonceS) != nonceSize {
		return Identity{}, fmt.Errorf(errPrefixPSK+"%w: server nonce length %d", ErrUnauthorized, len(nonceS))
	}
	wantServerMac := mac(clientEntry.key[:], macLabelServer, nonceC[:], nonceS)
	if subtle.ConstantTimeCompare(sp.GetMac(), wantServerMac) != 1 {
		return Identity{}, fmt.Errorf(errPrefixPSK+"%w: server mac mismatch", ErrUnauthorized)
	}

	clientMac := mac(clientEntry.key[:], macLabelClient, nonceS, nonceC[:])
	if err := writeAuth(stream, &api.AuthMessage{
		Kind: &api.AuthMessage_ClientProof{
			ClientProof: &api.ClientProof{Mac: clientMac},
		},
	}); err != nil {
		return Identity{}, fmt.Errorf(errPrefixPSK+"send client_proof: %w", err)
	}
	return clientEntry.identity, nil
}

// ServerHandshake implements [Authenticator]. Reads ClientHello,
// looks up the label-hinted entry (empty label maps to "owner"),
// computes and sends the matching ServerProof, then validates the
// ClientProof. On success returns the entry's Identity.
func (a *PSKAuth) ServerHandshake(_ context.Context, stream io.ReadWriteCloser) (Identity, error) {
	var hello api.AuthMessage
	if err := readAuth(stream, &hello); err != nil {
		return Identity{}, fmt.Errorf(errPrefixPSK+"read client_hello: %w", err)
	}
	ch := hello.GetClientHello()
	if ch == nil {
		return Identity{}, fmt.Errorf(errPrefixPSK+"%w: client sent %T, expected ClientHello", ErrUnauthorized, hello.GetKind())
	}
	nonceC := ch.GetNonce()
	if len(nonceC) != nonceSize {
		return Identity{}, fmt.Errorf(errPrefixPSK+"%w: client nonce length %d", ErrUnauthorized, len(nonceC))
	}

	label := ch.GetLabel()
	if label == "" {
		label = LabelOwner
	}
	srvEntry, ok := a.byLabel[label]
	if !ok {
		// Unknown label. Don't leak which labels exist — return the
		// standard handshake-failure surface.
		return Identity{}, fmt.Errorf(errPrefixPSK+"%w: unknown label", ErrUnauthorized)
	}

	nonceS, err := randomNonce()
	if err != nil {
		return Identity{}, fmt.Errorf(errPrefixPSK+"nonce: %w", err)
	}
	serverMac := mac(srvEntry.key[:], macLabelServer, nonceC, nonceS[:])
	if err := writeAuth(stream, &api.AuthMessage{
		Kind: &api.AuthMessage_ServerProof{
			ServerProof: &api.ServerProof{Nonce: nonceS[:], Mac: serverMac},
		},
	}); err != nil {
		return Identity{}, fmt.Errorf(errPrefixPSK+"send server_proof: %w", err)
	}

	var finish api.AuthMessage
	if err := readAuth(stream, &finish); err != nil {
		return Identity{}, fmt.Errorf(errPrefixPSK+"read client_proof: %w", err)
	}
	cp := finish.GetClientProof()
	if cp == nil {
		return Identity{}, fmt.Errorf(errPrefixPSK+"%w: client sent %T, expected ClientProof", ErrUnauthorized, finish.GetKind())
	}
	wantClientMac := mac(srvEntry.key[:], macLabelClient, nonceS[:], nonceC)
	if subtle.ConstantTimeCompare(cp.GetMac(), wantClientMac) != 1 {
		return Identity{}, fmt.Errorf(errPrefixPSK+"%w: client mac mismatch", ErrUnauthorized)
	}
	return srvEntry.identity, nil
}

// KeyHex returns the derived HMAC key of the first entry as hex.
// Test-only; only useful when there's a single configured entry.
func (a *PSKAuth) KeyHex() string {
	if len(a.order) == 0 {
		return ""
	}
	k := a.byLabel[a.order[0]].key
	return hex.EncodeToString(k[:])
}

// derivePSKKey runs HKDF-SHA256 to expand `secret` into 32 bytes.
func derivePSKKey(secret string) ([32]byte, error) {
	var out [32]byte
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte(pskInfo))
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, fmt.Errorf(errPrefixAuth+"derive PSK key: %w", err)
	}
	return out, nil
}

// mac computes HMAC-SHA256(key, label || nonceA || nonceB).
func mac(key []byte, label string, nonceA, nonceB []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(label))
	h.Write(nonceA)
	h.Write(nonceB)
	return h.Sum(nil)
}

func randomNonce() ([nonceSize]byte, error) {
	var n [nonceSize]byte
	if _, err := io.ReadFull(rand.Reader, n[:]); err != nil {
		return n, err
	}
	return n, nil
}

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

func writeAuth(w io.Writer, msg *api.AuthMessage) error {
	_, err := protodelim.MarshalTo(w, msg)
	return err
}

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
