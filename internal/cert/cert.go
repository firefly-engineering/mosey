// Package cert is the mosey workspace-certificate library: build
// signed claims that the workspace master vouches for an agent's
// identity + capabilities, and verify them against the master's
// public key. Lives in its own package so the auth Authenticator
// backend and the `mosey cert` CLI share one set of primitives.
//
// Cryptographic choices: Ed25519 for both the master key and the
// per-agent peer keys (consistent with libp2p, well-understood,
// constant-time verify). Signature input is the deterministically-
// serialized SignedCertContent — every byte the master commits to.
package cert

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/firefly-engineering/mosey/internal/api"
)

// CapsBit values mirror the bit positions in
// [api.SignedCertContent.CapsBits]. Public so the CLI can construct
// them; verifier code uses HasOwner / HasWrite / HasResize.
const (
	CapsBitOwner  uint32 = 1
	CapsBitWrite  uint32 = 2
	CapsBitResize uint32 = 4
)

// ErrInvalidSignature is returned by Verify when the cert's
// signature doesn't match the master's public key.
var ErrInvalidSignature = errors.New("cert: signature does not match master public key")

// ErrExpired is returned by Verify when the cert is outside its
// not_before / not_after window.
var ErrExpired = errors.New("cert: not within validity window")

// ErrRevoked is returned by Verify when the cert's serial is on
// the supplied revocation list.
var ErrRevoked = errors.New("cert: serial is revoked")

// ErrWrongWorkspace is returned by Verify when the cert's
// workspace_id doesn't match the verifier's expected workspace.
var ErrWrongWorkspace = errors.New("cert: workspace_id mismatch")

// Claim is the high-level Go view of [api.SignedCertContent]. The
// CLI builds these; Sign serializes one + signs it; Verify
// returns one after successful validation.
type Claim struct {
	AgentID     string
	PeerPubKey  ed25519.PublicKey
	Label       string
	CapsBits    uint32
	NotBefore   time.Time
	NotAfter    time.Time
	Serial      string
	WorkspaceID string
}

// HasOwner / HasWrite / HasResize are convenience accessors on the
// caps bitfield. Owner is special-cased to imply Write + Resize at
// the consumer layer (see auth.Identity) — these accessors return
// the raw bits without that implication.
func (c Claim) HasOwner() bool  { return c.CapsBits&CapsBitOwner != 0 }
func (c Claim) HasWrite() bool  { return c.CapsBits&CapsBitWrite != 0 }
func (c Claim) HasResize() bool { return c.CapsBits&CapsBitResize != 0 }

// Sign serializes claim into a deterministic payload, signs it
// with masterPriv, and returns the wire-form Cert envelope.
func Sign(masterPriv ed25519.PrivateKey, claim Claim) (*api.Cert, error) {
	if len(masterPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("cert: master private key length %d, want %d", len(masterPriv), ed25519.PrivateKeySize)
	}
	content := &api.SignedCertContent{
		AgentId:     claim.AgentID,
		PeerPubkey:  []byte(claim.PeerPubKey),
		Label:       claim.Label,
		CapsBits:    claim.CapsBits,
		NotBefore:   timestamppb.New(claim.NotBefore),
		NotAfter:    timestamppb.New(claim.NotAfter),
		Serial:      claim.Serial,
		WorkspaceId: claim.WorkspaceID,
	}
	payload, err := marshalDeterministic(content)
	if err != nil {
		return nil, fmt.Errorf("cert: marshal content: %w", err)
	}
	sig := ed25519.Sign(masterPriv, payload)
	return &api.Cert{Content: payload, Signature: sig}, nil
}

// VerifyOptions bundles the side-channel inputs a verifier needs
// beyond the cert itself: the master pubkey, the expected
// workspace id, the current time (overridable for tests), and the
// revocation set.
type VerifyOptions struct {
	MasterPub   ed25519.PublicKey
	WorkspaceID string

	// Now overrides time.Now() for the validity-window check.
	// Zero means "use the wall clock."
	Now time.Time

	// Revoked is the set of revoked serials. Cert is rejected if
	// its Serial appears here. Nil = none revoked.
	Revoked map[string]struct{}
}

// Verify checks the cert's signature against opts.MasterPub,
// asserts validity-window + workspace + revocation invariants, and
// returns the unpacked Claim on success.
func Verify(c *api.Cert, opts VerifyOptions) (Claim, error) {
	if c == nil {
		return Claim{}, errors.New("cert: nil")
	}
	if len(opts.MasterPub) != ed25519.PublicKeySize {
		return Claim{}, fmt.Errorf("cert: master public key length %d, want %d", len(opts.MasterPub), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(opts.MasterPub, c.GetContent(), c.GetSignature()) {
		return Claim{}, ErrInvalidSignature
	}
	var content api.SignedCertContent
	if err := proto.Unmarshal(c.GetContent(), &content); err != nil {
		return Claim{}, fmt.Errorf("cert: unmarshal content: %w", err)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	notBefore := content.GetNotBefore().AsTime()
	notAfter := content.GetNotAfter().AsTime()
	if now.Before(notBefore) || now.After(notAfter) {
		return Claim{}, fmt.Errorf("%w: now=%s not_before=%s not_after=%s", ErrExpired, now.Format(time.RFC3339), notBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339))
	}
	if opts.WorkspaceID != "" && content.GetWorkspaceId() != opts.WorkspaceID {
		return Claim{}, fmt.Errorf("%w: got %q want %q", ErrWrongWorkspace, content.GetWorkspaceId(), opts.WorkspaceID)
	}
	if _, revoked := opts.Revoked[content.GetSerial()]; revoked {
		return Claim{}, fmt.Errorf("%w: %s", ErrRevoked, content.GetSerial())
	}

	pub := content.GetPeerPubkey()
	if len(pub) != ed25519.PublicKeySize {
		return Claim{}, fmt.Errorf("cert: peer public key length %d, want %d", len(pub), ed25519.PublicKeySize)
	}

	return Claim{
		AgentID:     content.GetAgentId(),
		PeerPubKey:  ed25519.PublicKey(pub),
		Label:       content.GetLabel(),
		CapsBits:    content.GetCapsBits(),
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		Serial:      content.GetSerial(),
		WorkspaceID: content.GetWorkspaceId(),
	}, nil
}

// marshalDeterministic serializes msg with the deterministic flag
// so verify-side unmarshal+remarshal yields the same bytes the
// signer signed.
func marshalDeterministic(msg proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(msg)
}
