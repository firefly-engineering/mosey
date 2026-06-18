package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/protobuf/encoding/protodelim"

	"github.com/firefly-engineering/mosey/api"
	"github.com/firefly-engineering/mosey/wallet"
)

// walletNonceSize is the per-direction challenge length.
const walletNonceSize = 32

// Direction-specific transcript labels stop a signature being replayed
// the other way. The signed bytes are label || nonceA || nonceB ||
// session_id (see api/wallet.proto).
const (
	walletServerLabel = "mosey-wallet-v1:server"
	walletClientLabel = "mosey-wallet-v1:client"
)

const errPrefixWallet = "mosey/auth(wallet): "

// WalletAuth is an [Authenticator] backed by on-chain ownership and
// off-chain delegations. It is mutual but asymmetric:
//
//   - the server (session host) proves control of the session identity
//     (session_key) and authorizes the client from its delegation chain;
//   - the client proves control of an ephemeral connection key (K_c) and
//     presents the chain that roots K_c's caps in on-chain ownership.
//
// A given instance is built for one role: NewWalletServerAuth populates
// the listener side, NewWalletClientAuth the dialer side.
type WalletAuth struct {
	now func() time.Time

	// Server role.
	sessionPriv ed25519.PrivateKey
	sessionID   ed25519.PublicKey
	source      wallet.SnapshotSource

	// Client role.
	connPriv      ed25519.PrivateKey
	connPub       ed25519.PublicKey
	chain         []wallet.Delegation
	expectSession ed25519.PublicKey
}

// ServerOptions configures the listener side of WalletAuth.
type ServerOptions struct {
	// SessionKey is the persisted session keypair. Its public half is
	// the session identity registered on-chain. Required.
	SessionKey ed25519.PrivateKey
	// Source resolves on-chain ownership and grants. Required.
	Source wallet.SnapshotSource
	// Now overrides the clock (tests). Optional.
	Now func() time.Time
}

// ClientOptions configures the dialer side of WalletAuth.
type ClientOptions struct {
	// ConnKey is the ephemeral connection key K_c. The delegation
	// chain's leaf must delegate to its public half. Required.
	ConnKey ed25519.PrivateKey
	// Chain is the delegation chain (root → leaf) authorizing ConnKey.
	// Required.
	Chain []wallet.Delegation
	// ExpectSession, when set, is the session identity the dialer
	// intends to reach; the handshake fails if the server proves a
	// different one (MITM protection). Optional but recommended.
	ExpectSession ed25519.PublicKey
	// Now overrides the clock (tests). Optional.
	Now func() time.Time
}

// NewWalletServerAuth builds the listener side.
func NewWalletServerAuth(opts ServerOptions) (*WalletAuth, error) {
	if len(opts.SessionKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(errPrefixWallet+"SessionKey length %d, want %d", len(opts.SessionKey), ed25519.PrivateKeySize)
	}
	if opts.Source == nil {
		return nil, errors.New(errPrefixWallet + "Source required")
	}
	return &WalletAuth{
		now:         clockOr(opts.Now),
		sessionPriv: opts.SessionKey,
		sessionID:   opts.SessionKey.Public().(ed25519.PublicKey),
		source:      opts.Source,
	}, nil
}

// NewWalletClientAuth builds the dialer side.
func NewWalletClientAuth(opts ClientOptions) (*WalletAuth, error) {
	if len(opts.ConnKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(errPrefixWallet+"ConnKey length %d, want %d", len(opts.ConnKey), ed25519.PrivateKeySize)
	}
	if len(opts.Chain) == 0 {
		return nil, errors.New(errPrefixWallet + "Chain required")
	}
	return &WalletAuth{
		now:           clockOr(opts.Now),
		connPriv:      opts.ConnKey,
		connPub:       opts.ConnKey.Public().(ed25519.PublicKey),
		chain:         opts.Chain,
		expectSession: opts.ExpectSession,
	}, nil
}

func clockOr(f func() time.Time) func() time.Time {
	if f != nil {
		return f
	}
	return time.Now
}

// Name implements [Authenticator].
func (w *WalletAuth) Name() string { return "wallet" }

// SessionID returns the session identity this server-side authenticator
// proves control of (nil on a client-side instance). Useful for logging
// "session: <address>" at launch.
func (w *WalletAuth) SessionID() ed25519.PublicKey { return w.sessionID }

// ServerHandshake reads the client's WalletHello, proves control of the
// session key, verifies the client controls K_c, and folds the
// delegation chain into an Identity.
func (w *WalletAuth) ServerHandshake(ctx context.Context, stream io.ReadWriteCloser) (Identity, error) {
	if w.sessionPriv == nil || w.source == nil {
		return Identity{}, errors.New(errPrefixWallet + "instance is not configured as a server")
	}

	hello, err := readWalletHello(stream)
	if err != nil {
		return Identity{}, err
	}
	connPub := ed25519.PublicKey(hello.GetClientPubkey())
	if len(connPub) != ed25519.PublicKeySize {
		return Identity{}, fmt.Errorf(errPrefixWallet+"%w: client_pubkey length %d", ErrUnauthorized, len(connPub))
	}
	nonceC := hello.GetNonceC()
	if len(nonceC) != walletNonceSize {
		return Identity{}, fmt.Errorf(errPrefixWallet+"%w: nonce_c length %d", ErrUnauthorized, len(nonceC))
	}

	nonceS := make([]byte, walletNonceSize)
	if _, err := rand.Read(nonceS); err != nil {
		return Identity{}, fmt.Errorf(errPrefixWallet+"nonce: %w", err)
	}
	serverSig := ed25519.Sign(w.sessionPriv, walletTranscript(walletServerLabel, nonceC, nonceS, w.sessionID))
	challenge := &api.WalletHandshakeMessage{
		Kind: &api.WalletHandshakeMessage_Challenge{
			Challenge: &api.WalletChallenge{SessionKey: w.sessionID, NonceS: nonceS, ServerSig: serverSig},
		},
	}
	if err := writeWalletMsg(stream, challenge); err != nil {
		return Identity{}, fmt.Errorf(errPrefixWallet+"send challenge: %w", err)
	}

	proof, err := readWalletProof(stream)
	if err != nil {
		return Identity{}, err
	}
	if !ed25519.Verify(connPub, walletTranscript(walletClientLabel, nonceS, nonceC, w.sessionID), proof.GetClientSig()) {
		return Identity{}, fmt.Errorf(errPrefixWallet+"%w: client proof signature invalid", ErrUnauthorized)
	}

	caps, rootIsOwner, root, err := w.resolveCaps(ctx, apiToWalletChain(hello.GetDelegationChain()), connPub)
	if err != nil {
		return Identity{}, err
	}
	// Admin powers (SetMode/Promote/Kick) require the *full* cap set
	// flowing unbroken from the session owner — so a write-only or
	// view-only grant the owner signs to a viewer does not confer them.
	// Granting the complete set (incl. forge) is a deliberate "co-owner"
	// act. A grantee-rooted chain is never owner.
	owner := rootIsOwner && caps == wallet.AllCaps
	return Identity{
		Label: wallet.Address(root),
		Caps: Capabilities{
			Owner:  owner,
			Write:  caps.Has(wallet.CapWrite),
			Resize: caps.Has(wallet.CapResize),
		},
	}, nil
}

// ClientHandshake sends WalletHello, verifies the server controls the
// session it dialed, and signs the challenge with K_c.
func (w *WalletAuth) ClientHandshake(_ context.Context, stream io.ReadWriteCloser) (Identity, error) {
	if w.connPriv == nil {
		return Identity{}, errors.New(errPrefixWallet + "instance is not configured as a client")
	}

	nonceC := make([]byte, walletNonceSize)
	if _, err := rand.Read(nonceC); err != nil {
		return Identity{}, fmt.Errorf(errPrefixWallet+"nonce: %w", err)
	}
	hello := &api.WalletHandshakeMessage{
		Kind: &api.WalletHandshakeMessage_Hello{
			Hello: &api.WalletHello{
				ClientPubkey:    w.connPub,
				NonceC:          nonceC,
				DelegationChain: walletToAPIChain(w.chain),
			},
		},
	}
	if err := writeWalletMsg(stream, hello); err != nil {
		return Identity{}, fmt.Errorf(errPrefixWallet+"send hello: %w", err)
	}

	challenge, err := readWalletChallenge(stream)
	if err != nil {
		return Identity{}, err
	}
	sessionKey := ed25519.PublicKey(challenge.GetSessionKey())
	if len(sessionKey) != ed25519.PublicKeySize {
		return Identity{}, fmt.Errorf(errPrefixWallet+"%w: session_key length %d", ErrUnauthorized, len(sessionKey))
	}
	nonceS := challenge.GetNonceS()
	if len(nonceS) != walletNonceSize {
		return Identity{}, fmt.Errorf(errPrefixWallet+"%w: nonce_s length %d", ErrUnauthorized, len(nonceS))
	}
	if !ed25519.Verify(sessionKey, walletTranscript(walletServerLabel, nonceC, nonceS, sessionKey), challenge.GetServerSig()) {
		return Identity{}, fmt.Errorf(errPrefixWallet+"%w: server proof signature invalid", ErrUnauthorized)
	}
	if w.expectSession != nil && !w.expectSession.Equal(sessionKey) {
		return Identity{}, fmt.Errorf(errPrefixWallet+"%w: server presented session %s, expected %s",
			ErrUnauthorized, wallet.Address(sessionKey), wallet.Address(w.expectSession))
	}

	clientSig := ed25519.Sign(w.connPriv, walletTranscript(walletClientLabel, nonceS, nonceC, sessionKey))
	proof := &api.WalletHandshakeMessage{
		Kind: &api.WalletHandshakeMessage_Proof{Proof: &api.WalletProof{ClientSig: clientSig}},
	}
	if err := writeWalletMsg(stream, proof); err != nil {
		return Identity{}, fmt.Errorf(errPrefixWallet+"send proof: %w", err)
	}

	// The server's view is authoritative; this is a best-effort local
	// label reflecting the session reached and the leaf caps claimed.
	leafCaps, _ := leafCaps(w.chain)
	return Identity{
		Label: "wallet:" + wallet.Address(sessionKey),
		Caps: Capabilities{
			Write:  leafCaps.Has(wallet.CapWrite),
			Resize: leafCaps.Has(wallet.CapResize),
		},
	}, nil
}

// resolveCaps folds the chain against the current snapshot, applying the
// fail-open-within-budget and on-demand-verify-on-miss policies. It also
// returns the chain root (the human wallet identity) for labeling.
func (w *WalletAuth) resolveCaps(ctx context.Context, chain []wallet.Delegation, connPub ed25519.PublicKey) (wallet.Caps, bool, ed25519.PublicKey, error) {
	root, err := chainRoot(chain)
	if err != nil {
		return 0, false, nil, fmt.Errorf(errPrefixWallet+"%w: %w", ErrUnauthorized, err)
	}

	snap, fresh, err := w.source.Snapshot()
	if err != nil {
		return 0, false, nil, fmt.Errorf(errPrefixWallet+"no snapshot available: %w", err)
	}
	if !fresh {
		return 0, false, nil, errors.New(errPrefixWallet + "snapshot stale beyond budget; failing closed")
	}

	caps, isOwner, ferr := wallet.Fold(chain, connPub, w.sessionID, snap, w.now())
	if ferr == nil {
		return caps, isOwner, root, nil
	}
	// On a cache miss for the root, consult the source authoritatively
	// once before rejecting — admits a freshly-granted wallet without
	// waiting for the next refresh.
	if errors.Is(ferr, wallet.ErrUnknownRoot) {
		if gc, ok, verr := w.source.VerifyNow(ctx, root); verr == nil && ok {
			caps, isOwner, ferr = wallet.Fold(chain, connPub, w.sessionID, overlaySnapshot{Snapshot: snap, root: root, caps: gc}, w.now())
			if ferr == nil {
				return caps, isOwner, root, nil
			}
		}
	}
	return 0, false, nil, fmt.Errorf(errPrefixWallet+"%w: %w", ErrUnauthorized, ferr)
}

// overlaySnapshot augments a base Snapshot with one freshly-verified
// grant, for the on-demand-verify-on-miss path.
type overlaySnapshot struct {
	wallet.Snapshot
	root ed25519.PublicKey
	caps wallet.Caps
}

func (o overlaySnapshot) GrantCaps(w ed25519.PublicKey) (wallet.Caps, bool) {
	if o.root.Equal(w) {
		return o.caps, true
	}
	return o.Snapshot.GrantCaps(w)
}

func chainRoot(chain []wallet.Delegation) (ed25519.PublicKey, error) {
	if len(chain) == 0 {
		return nil, wallet.ErrEmptyChain
	}
	f, err := chain[0].Fields()
	if err != nil {
		return nil, err
	}
	return f.Delegator, nil
}

func leafCaps(chain []wallet.Delegation) (wallet.Caps, bool) {
	if len(chain) == 0 {
		return 0, false
	}
	f, err := chain[len(chain)-1].Fields()
	if err != nil {
		return 0, false
	}
	return f.Caps, true
}

func walletTranscript(label string, a, b, sessionID []byte) []byte {
	out := make([]byte, 0, len(label)+len(a)+len(b)+len(sessionID))
	out = append(out, label...)
	out = append(out, a...)
	out = append(out, b...)
	out = append(out, sessionID...)
	return out
}

func apiToWalletChain(in []*api.Delegation) []wallet.Delegation {
	out := make([]wallet.Delegation, len(in))
	for i, d := range in {
		out[i] = wallet.Delegation{Content: d.GetContent(), Signature: d.GetSignature()}
	}
	return out
}

func walletToAPIChain(in []wallet.Delegation) []*api.Delegation {
	out := make([]*api.Delegation, len(in))
	for i, d := range in {
		out[i] = &api.Delegation{Content: d.Content, Signature: d.Signature}
	}
	return out
}

func writeWalletMsg(wr io.Writer, msg *api.WalletHandshakeMessage) error {
	_, err := protodelim.MarshalTo(wr, msg)
	return err
}

func readWalletMsg(r io.Reader, msg *api.WalletHandshakeMessage) error {
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

func readWalletHello(r io.Reader) (*api.WalletHello, error) {
	var msg api.WalletHandshakeMessage
	if err := readWalletMsg(r, &msg); err != nil {
		return nil, fmt.Errorf(errPrefixWallet+"read hello: %w", err)
	}
	hello := msg.GetHello()
	if hello == nil {
		return nil, fmt.Errorf(errPrefixWallet+"%w: expected WalletHello, got %T", ErrUnauthorized, msg.GetKind())
	}
	return hello, nil
}

func readWalletChallenge(r io.Reader) (*api.WalletChallenge, error) {
	var msg api.WalletHandshakeMessage
	if err := readWalletMsg(r, &msg); err != nil {
		return nil, fmt.Errorf(errPrefixWallet+"read challenge: %w", err)
	}
	challenge := msg.GetChallenge()
	if challenge == nil {
		return nil, fmt.Errorf(errPrefixWallet+"%w: expected WalletChallenge, got %T", ErrUnauthorized, msg.GetKind())
	}
	return challenge, nil
}

func readWalletProof(r io.Reader) (*api.WalletProof, error) {
	var msg api.WalletHandshakeMessage
	if err := readWalletMsg(r, &msg); err != nil {
		return nil, fmt.Errorf(errPrefixWallet+"read proof: %w", err)
	}
	proof := msg.GetProof()
	if proof == nil {
		return nil, fmt.Errorf(errPrefixWallet+"%w: expected WalletProof, got %T", ErrUnauthorized, msg.GetKind())
	}
	return proof, nil
}
