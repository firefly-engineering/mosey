package wallet

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"
)

// contentHeader is line 1 of every delegation: a domain tag that
// separates these bytes from any other signMessage payload and pins the
// format version.
const contentHeader = "mosey session authorization v1"

// tsLayout renders timestamps as strict RFC3339 in UTC, seconds
// precision; a UTC time formats with a trailing "Z".
const tsLayout = time.RFC3339

// MaxChainDepth bounds delegation chain length, to cap verification cost
// and reject pathological inputs.
const MaxChainDepth = 8

// nonceSize is the fixed delegation nonce length in bytes.
const nonceSize = 16

// Errors returned while verifying delegations and chains.
var (
	ErrEmptyChain    = errors.New("wallet: empty delegation chain")
	ErrChainTooLong  = errors.New("wallet: delegation chain too long")
	ErrBadKey        = errors.New("wallet: malformed key")
	ErrBadSignature  = errors.New("wallet: bad delegation signature")
	ErrBrokenLink    = errors.New("wallet: delegation chain link mismatch")
	ErrLeafMismatch  = errors.New("wallet: chain leaf does not bind the connection key")
	ErrAttenuation   = errors.New("wallet: delegation widens caps beyond its delegator")
	ErrNotYetValid   = errors.New("wallet: delegation not yet valid")
	ErrExpired       = errors.New("wallet: delegation expired")
	ErrWrongSession  = errors.New("wallet: delegation is for a different session")
	ErrUnknownRoot   = errors.New("wallet: chain root has no live grant")
	ErrForgeRequired = errors.New("wallet: delegator lacks the forge capability")
)

// Fields are the semantic contents of a delegation, before signing.
type Fields struct {
	SessionID ed25519.PublicKey // the session this delegation is scoped to
	Delegator ed25519.PublicKey // the signer
	Delegate  ed25519.PublicKey // who receives the caps
	Caps      Caps
	NotBefore time.Time
	NotAfter  time.Time
	Nonce     []byte // 16 random bytes
}

// Render produces the canonical UTF-8 content bytes — the bytes a wallet
// signs. The grammar is fixed: header, blank line, then the fields in
// order, LF-joined, no trailing newline. Timestamps are truncated to the
// second and rendered in UTC.
func (f Fields) Render() []byte {
	lines := []string{
		contentHeader,
		"",
		"session: " + base58Encode(f.SessionID),
		"delegator: " + base58Encode(f.Delegator),
		"delegate: " + base58Encode(f.Delegate),
		"caps: " + f.Caps.String(),
		"not-before: " + renderTime(f.NotBefore),
		"not-after: " + renderTime(f.NotAfter),
		"nonce: " + base58Encode(f.Nonce),
	}
	return []byte(strings.Join(lines, "\n"))
}

func renderTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(tsLayout)
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("wallet: bad timestamp %q: %w", s, err)
	}
	if renderTime(t) != s { // reject +00:00, fractional seconds, etc.
		return time.Time{}, fmt.Errorf("wallet: non-canonical timestamp %q", s)
	}
	return t.UTC(), nil
}

// ParseContent strictly parses canonical delegation content back into
// Fields. Anything off-grammar is rejected, never coerced.
func ParseContent(content []byte) (Fields, error) {
	lines := strings.Split(string(content), "\n")
	if len(lines) != 9 {
		return Fields{}, fmt.Errorf("wallet: delegation has %d lines, want 9", len(lines))
	}
	if lines[0] != contentHeader {
		return Fields{}, fmt.Errorf("wallet: bad delegation header %q", lines[0])
	}
	if lines[1] != "" {
		return Fields{}, errors.New("wallet: delegation line 2 must be blank")
	}

	field := func(i int, key string) (string, error) {
		prefix := key + ": "
		if !strings.HasPrefix(lines[i], prefix) {
			return "", fmt.Errorf("wallet: line %d is not %q", i+1, key)
		}
		return lines[i][len(prefix):], nil
	}
	key32 := func(i int, name string) (ed25519.PublicKey, error) {
		s, err := field(i, name)
		if err != nil {
			return nil, err
		}
		b, err := base58Decode(s)
		if err != nil {
			return nil, err
		}
		if len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("wallet: %s is %d bytes, want 32", name, len(b))
		}
		return ed25519.PublicKey(b), nil
	}

	var f Fields
	var err error
	if f.SessionID, err = key32(2, "session"); err != nil {
		return Fields{}, err
	}
	if f.Delegator, err = key32(3, "delegator"); err != nil {
		return Fields{}, err
	}
	if f.Delegate, err = key32(4, "delegate"); err != nil {
		return Fields{}, err
	}
	capsStr, err := field(5, "caps")
	if err != nil {
		return Fields{}, err
	}
	if f.Caps, err = ParseCaps(capsStr); err != nil {
		return Fields{}, err
	}
	nbStr, err := field(6, "not-before")
	if err != nil {
		return Fields{}, err
	}
	if f.NotBefore, err = parseTime(nbStr); err != nil {
		return Fields{}, err
	}
	naStr, err := field(7, "not-after")
	if err != nil {
		return Fields{}, err
	}
	if f.NotAfter, err = parseTime(naStr); err != nil {
		return Fields{}, err
	}
	nonceStr, err := field(8, "nonce")
	if err != nil {
		return Fields{}, err
	}
	if f.Nonce, err = base58Decode(nonceStr); err != nil {
		return Fields{}, err
	}
	if len(f.Nonce) != nonceSize {
		return Fields{}, fmt.Errorf("wallet: nonce is %d bytes, want %d", len(f.Nonce), nonceSize)
	}
	return f, nil
}

// Delegation is the wire envelope: canonical content plus an Ed25519
// signature over it by the delegator named inside.
type Delegation struct {
	Content   []byte
	Signature []byte
}

// Sign renders f and signs it with priv, returning the delegation. priv
// must be the key matching f.Delegator.
func Sign(priv ed25519.PrivateKey, f Fields) Delegation {
	content := f.Render()
	return Delegation{Content: content, Signature: ed25519.Sign(priv, content)}
}

// Fields parses (without verifying) the delegation's content.
func (d Delegation) Fields() (Fields, error) { return ParseContent(d.Content) }

// Verify parses the content and checks the signature against the
// delegator named inside, returning the parsed Fields on success.
func (d Delegation) Verify() (Fields, error) {
	f, err := d.Fields()
	if err != nil {
		return Fields{}, err
	}
	if len(f.Delegator) != ed25519.PublicKeySize {
		return Fields{}, ErrBadKey
	}
	if len(d.Signature) != ed25519.SignatureSize {
		return Fields{}, ErrBadSignature
	}
	if !ed25519.Verify(f.Delegator, d.Content, d.Signature) {
		return Fields{}, ErrBadSignature
	}
	return f, nil
}

// Fold validates a delegation chain (root → leaf) for sessionID against
// snap at time now, and returns the effective caps the connection key
// (leafPub) wields plus whether the chain is rooted at the session
// owner. The chain must: carry valid signatures; be scoped to sessionID
// and live at now; join link-to-link and terminate at leafPub; attenuate
// monotonically from the root's on-chain caps; and have FORGE at every
// non-leaf delegator (the leaf hop authorizes the holder's own
// connection key and needs no forge).
func Fold(chain []Delegation, leafPub, sessionID ed25519.PublicKey, snap Snapshot, now time.Time) (caps Caps, rootIsOwner bool, err error) {
	if len(chain) == 0 {
		return 0, false, ErrEmptyChain
	}
	if len(chain) > MaxChainDepth {
		return 0, false, ErrChainTooLong
	}

	fields := make([]Fields, len(chain))
	for i, d := range chain {
		f, verr := d.Verify()
		if verr != nil {
			return 0, false, verr
		}
		if !sessionID.Equal(f.SessionID) {
			return 0, false, ErrWrongSession
		}
		if now.Before(f.NotBefore) {
			return 0, false, ErrNotYetValid
		}
		if now.After(f.NotAfter) {
			return 0, false, ErrExpired
		}
		fields[i] = f
	}

	for i := 0; i < len(fields)-1; i++ {
		if !fields[i].Delegate.Equal(fields[i+1].Delegator) {
			return 0, false, ErrBrokenLink
		}
	}
	if !fields[len(fields)-1].Delegate.Equal(leafPub) {
		return 0, false, ErrLeafMismatch
	}

	root := fields[0].Delegator
	var rootCaps Caps
	if root.Equal(snap.Owner()) {
		rootCaps, rootIsOwner = AllCaps, true
	} else {
		gc, ok := snap.GrantCaps(root)
		if !ok {
			return 0, false, ErrUnknownRoot
		}
		rootCaps = gc
	}

	// Attenuation: hop 0 ⊆ rootCaps, then each hop ⊆ the previous.
	effective := rootCaps
	for i := range fields {
		if !fields[i].Caps.Subset(effective) {
			return 0, false, ErrAttenuation
		}
		effective = fields[i].Caps
	}

	// Every non-leaf delegator must hold FORGE. The delegator of hop i
	// holds the caps granted into it: rootCaps for hop 0, else the caps
	// of the delegation that named it as delegate.
	for i := 0; i < len(fields)-1; i++ {
		delegatorCaps := rootCaps
		if i > 0 {
			delegatorCaps = fields[i-1].Caps
		}
		if !delegatorCaps.Has(CapForge) {
			return 0, false, ErrForgeRequired
		}
	}

	return effective, rootIsOwner, nil
}
