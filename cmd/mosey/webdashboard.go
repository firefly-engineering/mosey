// Dashboard + multi-session selection for `mosey web`. In multi-session
// mode (--wallet-login with --wallet-rpc/--wallet-program), the gateway
// lists a wallet's sessions from the chain and dials whichever one the
// browser picks — by session_key, resolved via the DHT — instead of a
// single fixed --target.
package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/firefly-engineering/mosey/wallet"
	"github.com/firefly-engineering/mosey/walletsolana"
)

// sessionLister is the chain read the dashboard needs — satisfied by
// *walletsolana.Source, faked in tests.
type sessionLister interface {
	SessionsByOwner(ctx context.Context, owner ed25519.PublicKey) ([]walletsolana.OwnedSession, error)
}

// sessionTarget converts a session_key (an Ed25519 public key, the
// on-chain session identity) into the dial string the libp2p backend
// resolves via the DHT: "/p2p/<peer-id>". The host runs this key as its
// libp2p identity, so its peer id is derived from it.
func sessionTarget(sessionKey ed25519.PublicKey) (string, error) {
	pub, err := ic.UnmarshalEd25519PublicKey(sessionKey)
	if err != nil {
		return "", fmt.Errorf("session key → libp2p key: %w", err)
	}
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("session key → peer id: %w", err)
	}
	return "/p2p/" + id.String(), nil
}

// handleSessions lists the connected wallet's sessions for the
// dashboard. Request: GET /sessions?wallet=<base58>. Pure chain read.
func (g *webGateway) handleSessions(w http.ResponseWriter, r *http.Request) {
	if g.lister == nil {
		http.Error(w, "dashboard not configured", http.StatusNotFound)
		return
	}
	owner, err := wallet.ParseAddress(r.URL.Query().Get("wallet"))
	if err != nil {
		http.Error(w, "bad or missing wallet", http.StatusBadRequest)
		return
	}
	sessions, err := g.lister.SessionsByOwner(r.Context(), owner)
	if err != nil {
		g.logger.Warn("mosey web: dashboard list", "err", err)
		http.Error(w, "list sessions failed", http.StatusBadGateway)
		return
	}
	out := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, map[string]any{
			"session": wallet.Address(s.SessionKey),
			"address": s.Address,
			"epoch":   s.Epoch,
		})
	}
	writeJSON(w, map[string]any{"sessions": out})
}
