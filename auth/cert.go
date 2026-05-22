package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protodelim"

	"github.com/firefly-engineering/mosey/api"
	"github.com/firefly-engineering/mosey/cert"
)

// certNonceSize is the per-direction proof-of-control challenge
// length. 32 random bytes; signed by the peer's private key as
// proof it controls the public key declared in its cert.
const certNonceSize = 32

// certProofLabel is folded into the bytes the peer signs so a
// signature over the auth nonce can't be replayed as a signature
// over something else.
const certProofLabel = "mosey-cert-v1"

// errPrefixCert is the leading tag on every error this file emits.
// Keeps subsystem attribution consistent without repeating the
// literal at every fmt.Errorf site. Sibling files in the auth
// package carry their own prefix constants.
const errPrefixCert = "mosey/auth(cert): "

// CertAuth is an [Authenticator] backed by a workspace master key
// + per-agent certs. Mutual cert exchange + nonce challenge proves
// each side both holds a valid cert AND controls the private key
// matching the cert's declared peer_pubkey.
//
// On successful handshake, both sides decode the peer's Caps from
// the cert and return the matching Identity. The label surfaces
// the cert's Label field (agent_id or human name).
type CertAuth struct {
	// Local material: the cert we present, and the private key we
	// use to sign the nonce challenge.
	localCert *api.Cert
	localPriv ed25519.PrivateKey

	// Verifier-side material: the master pubkey we validate peers
	// against, the expected workspace id, and the revocation set.
	masterPub   ed25519.PublicKey
	workspaceID string

	revokedMu sync.RWMutex
	revoked   map[string]struct{}
}

// CertAuthOptions configures a [CertAuth].
type CertAuthOptions struct {
	// LocalCert is the cert this side presents during the
	// handshake. Required.
	LocalCert *api.Cert

	// LocalPriv is the Ed25519 private key matching
	// LocalCert.PeerPubKey. Required.
	LocalPriv ed25519.PrivateKey

	// MasterPub is the master public key the verifier uses to
	// authenticate the peer's cert. Required.
	MasterPub ed25519.PublicKey

	// WorkspaceID is the expected workspace; certs whose
	// workspace_id doesn't match are rejected. Required.
	WorkspaceID string

	// Revoked is the initial set of revoked serials. May be nil;
	// callers can mutate at runtime via UpdateRevoked.
	Revoked map[string]struct{}
}

// NewCertAuth builds a CertAuth from opts. Validates the local
// cert against the master pubkey up-front so configuration errors
// surface at construction rather than first-connect.
func NewCertAuth(opts CertAuthOptions) (*CertAuth, error) {
	if opts.LocalCert == nil {
		return nil, errors.New(errPrefixCert + "LocalCert required")
	}
	if len(opts.LocalPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(errPrefixCert+"LocalPriv length %d, want %d", len(opts.LocalPriv), ed25519.PrivateKeySize)
	}
	if len(opts.MasterPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(errPrefixCert+"MasterPub length %d, want %d", len(opts.MasterPub), ed25519.PublicKeySize)
	}
	if opts.WorkspaceID == "" {
		return nil, errors.New(errPrefixCert + "WorkspaceID required")
	}
	claim, err := cert.Verify(opts.LocalCert, cert.VerifyOptions{
		MasterPub:   opts.MasterPub,
		WorkspaceID: opts.WorkspaceID,
		Revoked:     opts.Revoked,
	})
	if err != nil {
		return nil, fmt.Errorf(errPrefixCert+"local cert invalid: %w", err)
	}
	// Sanity check: peer_pubkey in cert must match the public half
	// of localPriv. Otherwise the nonce-signing step on the peer's
	// side won't validate.
	if !pubKeyMatches(claim.PeerPubKey, opts.LocalPriv) {
		return nil, errors.New(errPrefixCert + "LocalPriv does not match LocalCert.peer_pubkey")
	}

	revoked := map[string]struct{}{}
	for k := range opts.Revoked {
		revoked[k] = struct{}{}
	}
	return &CertAuth{
		localCert:   opts.LocalCert,
		localPriv:   opts.LocalPriv,
		masterPub:   opts.MasterPub,
		workspaceID: opts.WorkspaceID,
		revoked:     revoked,
	}, nil
}

// Name implements [Authenticator].
func (c *CertAuth) Name() string { return "cert" }

// UpdateRevoked replaces the revocation set. Call after reloading
// the revocation file on a SIGHUP or when new entries arrive over
// pubsub (future). Cheap — just swaps the underlying map.
func (c *CertAuth) UpdateRevoked(revoked map[string]struct{}) {
	c.revokedMu.Lock()
	defer c.revokedMu.Unlock()
	c.revoked = revoked
}

func (c *CertAuth) revokedSnapshot() map[string]struct{} {
	c.revokedMu.RLock()
	defer c.revokedMu.RUnlock()
	out := make(map[string]struct{}, len(c.revoked))
	for k := range c.revoked {
		out[k] = struct{}{}
	}
	return out
}

// ClientHandshake / ServerHandshake are symmetric for CertAuth:
// each side sends its CertHello (cert + fresh nonce) and replies
// with a SignedNonce over the peer's nonce. Both sides verify the
// signature against the peer's cert and return the Identity built
// from the cert's caps.

func (c *CertAuth) ClientHandshake(_ context.Context, stream io.ReadWriteCloser) (Identity, error) {
	return c.runHandshake(stream, true)
}

func (c *CertAuth) ServerHandshake(_ context.Context, stream io.ReadWriteCloser) (Identity, error) {
	return c.runHandshake(stream, false)
}

// runHandshake is the symmetric body. clientFirst flips the
// send/receive order so we don't deadlock on the unbuffered side.
func (c *CertAuth) runHandshake(stream io.ReadWriteCloser, clientFirst bool) (Identity, error) {
	myNonce := make([]byte, certNonceSize)
	if _, err := rand.Read(myNonce); err != nil {
		return Identity{}, fmt.Errorf(errPrefixCert+"nonce: %w", err)
	}

	helloOut := &api.CertHandshakeMessage{
		Payload: &api.CertHandshakeMessage_Hello{
			Hello: &api.CertHello{Cert: c.localCert, Nonce: myNonce},
		},
	}

	var (
		peerHello *api.CertHello
		err       error
	)
	if clientFirst {
		if err = writeCertMsg(stream, helloOut); err != nil {
			return Identity{}, fmt.Errorf(errPrefixCert+"send hello: %w", err)
		}
		peerHello, err = readCertHello(stream)
		if err != nil {
			return Identity{}, err
		}
	} else {
		peerHello, err = readCertHello(stream)
		if err != nil {
			return Identity{}, err
		}
		if err = writeCertMsg(stream, helloOut); err != nil {
			return Identity{}, fmt.Errorf(errPrefixCert+"send hello: %w", err)
		}
	}

	peerClaim, err := cert.Verify(peerHello.GetCert(), cert.VerifyOptions{
		MasterPub:   c.masterPub,
		WorkspaceID: c.workspaceID,
		Revoked:     c.revokedSnapshot(),
	})
	if err != nil {
		return Identity{}, fmt.Errorf(errPrefixCert+"peer cert: %w: %w", ErrUnauthorized, err)
	}
	if len(peerHello.GetNonce()) != certNonceSize {
		return Identity{}, fmt.Errorf(errPrefixCert+"%w: peer nonce length %d", ErrUnauthorized, len(peerHello.GetNonce()))
	}

	// Sign the PEER's nonce and send our SignedNonce.
	mySig := ed25519.Sign(c.localPriv, append([]byte(certProofLabel), peerHello.GetNonce()...))
	proofOut := &api.CertHandshakeMessage{
		Payload: &api.CertHandshakeMessage_Proof{
			Proof: &api.SignedNonce{Signature: mySig},
		},
	}

	var peerProof *api.SignedNonce
	if clientFirst {
		if err = writeCertMsg(stream, proofOut); err != nil {
			return Identity{}, fmt.Errorf(errPrefixCert+"send proof: %w", err)
		}
		peerProof, err = readCertProof(stream)
		if err != nil {
			return Identity{}, err
		}
	} else {
		peerProof, err = readCertProof(stream)
		if err != nil {
			return Identity{}, err
		}
		if err = writeCertMsg(stream, proofOut); err != nil {
			return Identity{}, fmt.Errorf(errPrefixCert+"send proof: %w", err)
		}
	}

	// Verify peer's signature over OUR nonce against their cert's
	// declared peer_pubkey.
	signedBytes := append([]byte(certProofLabel), myNonce...)
	if !ed25519.Verify(peerClaim.PeerPubKey, signedBytes, peerProof.GetSignature()) {
		return Identity{}, fmt.Errorf(errPrefixCert+"%w: peer proof signature invalid", ErrUnauthorized)
	}

	return claimToIdentity(peerClaim), nil
}

// claimToIdentity maps a verified Claim to the higher-level
// Identity surface. Owner is special-cased to imply Write +
// Resize at the consumer layer, matching the PSK identity shape.
func claimToIdentity(c cert.Claim) Identity {
	return Identity{
		Label: c.Label,
		Caps: Capabilities{
			Owner:  c.HasOwner(),
			Write:  c.HasWrite() || c.HasOwner(),
			Resize: c.HasResize() || c.HasOwner(),
		},
	}
}

func pubKeyMatches(pub ed25519.PublicKey, priv ed25519.PrivateKey) bool {
	if len(priv) != ed25519.PrivateKeySize {
		return false
	}
	derivedPub := priv.Public().(ed25519.PublicKey)
	if len(pub) != len(derivedPub) {
		return false
	}
	for i := range pub {
		if pub[i] != derivedPub[i] {
			return false
		}
	}
	return true
}

func writeCertMsg(w io.Writer, msg *api.CertHandshakeMessage) error {
	_, err := protodelim.MarshalTo(w, msg)
	return err
}

func readCertMsg(r io.Reader, msg *api.CertHandshakeMessage) error {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = &singleByteReader{r: r}
	}
	adapter := struct {
		io.Reader
		io.ByteReader
	}{Reader: r, ByteReader: br}
	return protodelim.UnmarshalFrom(adapter, msg)
}

func readCertHello(r io.Reader) (*api.CertHello, error) {
	var msg api.CertHandshakeMessage
	if err := readCertMsg(r, &msg); err != nil {
		return nil, fmt.Errorf(errPrefixCert+"read hello: %w", err)
	}
	hello := msg.GetHello()
	if hello == nil {
		return nil, fmt.Errorf(errPrefixCert+"%w: expected CertHello, got %T", ErrUnauthorized, msg.GetPayload())
	}
	return hello, nil
}

func readCertProof(r io.Reader) (*api.SignedNonce, error) {
	var msg api.CertHandshakeMessage
	if err := readCertMsg(r, &msg); err != nil {
		return nil, fmt.Errorf(errPrefixCert+"read proof: %w", err)
	}
	proof := msg.GetProof()
	if proof == nil {
		return nil, fmt.Errorf(errPrefixCert+"%w: expected SignedNonce, got %T", ErrUnauthorized, msg.GetPayload())
	}
	return proof, nil
}

// Compile-time placeholder so future cert-validity caching gets a
// stable home.
var _ = time.Now
