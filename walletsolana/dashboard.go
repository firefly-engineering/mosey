package walletsolana

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/firefly-engineering/mosey/wallet"
)

// OwnedSession is one session a wallet owns, as listed for the web
// dashboard ("which sessions can I reach"). SessionKey doubles as the
// libp2p peer id to dial; Address is the on-chain PDA.
type OwnedSession struct {
	SessionKey ed25519.PublicKey
	Address    string
	Epoch      uint16
}

// ownerOffset is the byte offset of Session.owner in account data:
// 8-byte discriminator + 32-byte session_key.
const ownerOffset = 8 + 32

// SessionsByOwner lists the sessions owned by owner via a
// getProgramAccounts filtered on the Session account's owner field. It
// is the read side of the dashboard — a pure RPC read needing only the
// wallet's public key, no signature. The program/RPC are taken from the
// Source's configuration.
func (s *Source) SessionsByOwner(ctx context.Context, owner ed25519.PublicKey) ([]OwnedSession, error) {
	if len(owner) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("walletsolana: owner length %d, want %d", len(owner), ed25519.PublicKeySize)
	}
	raw, err := s.call(ctx, "getProgramAccounts", []any{
		s.programID,
		map[string]any{
			"encoding":   "base64",
			"commitment": s.commitment,
			"filters": []any{
				map[string]any{"memcmp": map[string]any{
					"offset": ownerOffset,
					"bytes":  wallet.EncodeBase58(owner),
				}},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	var accounts []rpcAccount
	if err := json.Unmarshal(raw, &accounts); err != nil {
		return nil, fmt.Errorf("walletsolana: decode getProgramAccounts: %w", err)
	}

	var out []OwnedSession
	for _, a := range accounts {
		if len(a.Account.Data) == 0 {
			continue
		}
		data, derr := base64.StdEncoding.DecodeString(a.Account.Data[0])
		if derr != nil || len(data) < 8 || [8]byte(data[:8]) != sessionDisc {
			continue
		}
		dec, derr := decodeSession(data)
		if derr != nil {
			continue
		}
		out = append(out, OwnedSession{
			SessionKey: dec.SessionKey,
			Address:    a.Pubkey,
			Epoch:      dec.Epoch,
		})
	}
	return out, nil
}
