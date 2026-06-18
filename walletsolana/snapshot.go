package walletsolana

import (
	"crypto/ed25519"
	"time"

	"github.com/firefly-engineering/mosey/wallet"
)

// snapshot is an immutable wallet.Snapshot built from decoded on-chain
// accounts, with epoch + expiry liveness already applied (dead grants
// simply don't appear).
type snapshot struct {
	owner  ed25519.PublicKey
	grants map[string]wallet.Caps
}

func buildSnapshot(s *Session, grants []*Grant, now time.Time) *snapshot {
	out := &snapshot{owner: s.Owner, grants: make(map[string]wallet.Caps, len(grants))}
	for _, g := range grants {
		if g.Epoch != s.Epoch { // swept by bump_epoch
			continue
		}
		if g.Expiry != 0 && g.Expiry <= now.Unix() { // expired
			continue
		}
		out.grants[string(g.Grantee)] = g.Caps
	}
	return out
}

func (s *snapshot) Owner() ed25519.PublicKey { return s.owner }

func (s *snapshot) GrantCaps(w ed25519.PublicKey) (wallet.Caps, bool) {
	c, ok := s.grants[string(w)]
	return c, ok
}
