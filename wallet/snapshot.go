package wallet

import (
	"context"
	"crypto/ed25519"
)

// Snapshot is a point-in-time view of one session's on-chain
// authorization state, with epoch and expiry liveness already applied
// (a grant that is epoch-swept or past its expiry simply does not
// appear). It is read-only and safe for concurrent use.
type Snapshot interface {
	// Owner is the session owner's wallet. The owner implicitly holds
	// AllCaps.
	Owner() ed25519.PublicKey

	// GrantCaps reports the live grant caps for wallet and whether any
	// live grant exists. It does not account for ownership — callers
	// compare against Owner separately.
	GrantCaps(wallet ed25519.PublicKey) (Caps, bool)
}

// SnapshotSource hands the authenticator the current Snapshot. The
// Solana-backed implementation refreshes it in the background; the
// in-memory MemSource serves tests and the --wallet-dev-owner stub.
//
// The hot path calls Snapshot and never blocks on RPC. VerifyNow is the
// deliberate exception, used only on a cache miss.
type SnapshotSource interface {
	// Snapshot returns the current cached view. fresh reports whether
	// the source confirmed freshness within its staleness budget; when
	// false the caller must fail closed (admit nothing new). err is
	// non-nil only at cold start, before any snapshot has loaded.
	Snapshot() (snap Snapshot, fresh bool, err error)

	// VerifyNow performs a blocking, authoritative lookup for one
	// wallet, bypassing the cache — used on a cache miss to admit a
	// freshly-granted wallet without waiting for the next refresh. It
	// must only ever admit a wallet that holds a real on-chain grant.
	VerifyNow(ctx context.Context, wallet ed25519.PublicKey) (caps Caps, ok bool, err error)
}
