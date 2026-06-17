// Package wallet implements the credential logic for mosey's wallet
// authenticator: capability bits, off-chain delegations, and the
// SnapshotSource seam that resolves on-chain ownership and grants.
//
// It mirrors the role the cert package plays for cert auth, and depends
// on no other mosey package — so the auth layer can translate a
// wallet.Caps into an auth.Capabilities without an import cycle.
package wallet

import (
	"fmt"
	"strings"
)

// Caps is the on-chain / delegation capability bitmask. It has no
// "owner" bit on purpose: ownership is the structural Session.owner
// field, and the owner implicitly holds every cap. The bit values and
// the String/ParseCaps rendering match the canonical delegation text in
// docs/src/wallet-auth.md#wire-format.
type Caps uint8

const (
	CapWrite  Caps = 1 << 0 // send keystrokes to the PTY
	CapResize Caps = 1 << 1 // resize the PTY
	CapForge  Caps = 1 << 2 // may sign off-chain delegations rooted at this grant
)

// AllCaps is the implicit cap set of a session owner.
const AllCaps = CapWrite | CapResize | CapForge

// Has reports whether c grants every bit in x.
func (c Caps) Has(x Caps) bool { return c&x == x }

// Subset reports whether c grants nothing beyond of — the attenuation
// invariant every delegation hop must satisfy (child ⊆ parent).
func (c Caps) Subset(of Caps) bool { return c&^of == 0 }

// String renders the caps as the canonical delegation text does: the
// present bits in the fixed order "write, resize, forge", comma-space
// joined, with the empty set rendered as "view-only".
func (c Caps) String() string {
	var parts []string
	if c.Has(CapWrite) {
		parts = append(parts, "write")
	}
	if c.Has(CapResize) {
		parts = append(parts, "resize")
	}
	if c.Has(CapForge) {
		parts = append(parts, "forge")
	}
	if len(parts) == 0 {
		return "view-only"
	}
	return strings.Join(parts, ", ")
}

// ParseCaps is the strict inverse of String: it accepts only the exact
// canonical rendering (fixed order, comma-space, "view-only" for empty)
// and rejects duplicates, reordering, or unknown tokens. This keeps the
// signed delegation bytes unambiguous.
func ParseCaps(s string) (Caps, error) {
	if s == "view-only" {
		return 0, nil
	}
	var c Caps
	for tok := range strings.SplitSeq(s, ", ") {
		switch tok {
		case "write":
			c |= CapWrite
		case "resize":
			c |= CapResize
		case "forge":
			c |= CapForge
		default:
			return 0, fmt.Errorf("wallet: invalid caps token %q in %q", tok, s)
		}
	}
	if c.String() != s {
		return 0, fmt.Errorf("wallet: non-canonical caps %q (want %q)", s, c.String())
	}
	return c, nil
}
