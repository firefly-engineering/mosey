// On-chain governance for `mosey web`: transfer ownership, on-chain
// grant, and bump-epoch (mass-revoke). The gateway BUILDS the unsigned
// transaction (reusing walletsolana) and the browser wallet SIGNS it —
// the gateway never holds owner authority. /govern/build returns the
// unsigned tx; the page signs it (web3.js signTransaction) and posts the
// signed bytes to /govern/submit. See docs/src/web-attach.md.
//
// Browser-side signing + submission is verified against devnet, not in
// the Go test suite; the build + submit-routing below are unit-tested
// with a fake governor.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/firefly-engineering/mosey/wallet"
)

// governor builds unsigned governance transactions for browser signing
// and submits the signed result — satisfied by *walletsolana.Source,
// faked in tests.
type governor interface {
	BuildTransferOwnership(ctx context.Context, ownerPub, sessionKey, newOwner ed25519.PublicKey) ([]byte, error)
	BuildGrant(ctx context.Context, ownerPub, sessionKey, grantee ed25519.PublicKey, caps uint8, expiry int64) ([]byte, error)
	BuildBumpEpoch(ctx context.Context, ownerPub, sessionKey ed25519.PublicKey) ([]byte, error)
	BuildRevoke(ctx context.Context, ownerPub, sessionKey, grantee ed25519.PublicKey) ([]byte, error)
	SubmitSigned(ctx context.Context, tx []byte) (string, error)
}

// handleGovernBuild builds an unsigned governance transaction for the
// browser wallet to sign. Request: {op, wallet, session, ...op-params}.
// Response: {tx_base64}.
func (g *webGateway) handleGovernBuild(w http.ResponseWriter, r *http.Request) {
	if g.gov == nil {
		http.Error(w, "governance not configured", http.StatusNotFound)
		return
	}
	var req struct {
		Op       string `json:"op"` // transfer | grant | bump
		Wallet   string `json:"wallet"`
		Session  string `json:"session"`
		NewOwner string `json:"new_owner"`
		Grantee  string `json:"grantee"`
		Caps     string `json:"caps"`
		Expiry   int64  `json:"expiry"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	owner, err := wallet.ParseAddress(req.Wallet)
	if err != nil {
		http.Error(w, "bad wallet", http.StatusBadRequest)
		return
	}
	session := g.sessionKey
	if g.multiSession {
		if session, err = wallet.ParseAddress(req.Session); err != nil {
			http.Error(w, "bad or missing session", http.StatusBadRequest)
			return
		}
	}

	var tx []byte
	switch req.Op {
	case "transfer":
		newOwner, err := wallet.ParseAddress(req.NewOwner)
		if err != nil {
			http.Error(w, "bad new_owner", http.StatusBadRequest)
			return
		}
		tx, err = g.gov.BuildTransferOwnership(r.Context(), owner, session, newOwner)
		if err != nil {
			g.governError(w, err)
			return
		}
	case "grant":
		grantee, err := wallet.ParseAddress(req.Grantee)
		if err != nil {
			http.Error(w, "bad grantee", http.StatusBadRequest)
			return
		}
		caps := wallet.Caps(0)
		if req.Caps != "" {
			if caps, err = wallet.ParseCapsLenient(req.Caps); err != nil {
				http.Error(w, "bad caps", http.StatusBadRequest)
				return
			}
		}
		tx, err = g.gov.BuildGrant(r.Context(), owner, session, grantee, uint8(caps), req.Expiry)
		if err != nil {
			g.governError(w, err)
			return
		}
	case "bump":
		tx, err = g.gov.BuildBumpEpoch(r.Context(), owner, session)
		if err != nil {
			g.governError(w, err)
			return
		}
	case "revoke":
		grantee, err := wallet.ParseAddress(req.Grantee)
		if err != nil {
			http.Error(w, "bad grantee", http.StatusBadRequest)
			return
		}
		tx, err = g.gov.BuildRevoke(r.Context(), owner, session, grantee)
		if err != nil {
			g.governError(w, err)
			return
		}
	default:
		http.Error(w, "unknown op (want transfer|grant|revoke|bump)", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"tx_base64": base64.StdEncoding.EncodeToString(tx)})
}

// handleGovernSubmit submits a browser-signed governance transaction.
// Request: {tx_base64}. Response: {signature}.
func (g *webGateway) handleGovernSubmit(w http.ResponseWriter, r *http.Request) {
	if g.gov == nil {
		http.Error(w, "governance not configured", http.StatusNotFound)
		return
	}
	var req struct {
		TxBase64 string `json:"tx_base64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tx, err := base64.StdEncoding.DecodeString(req.TxBase64)
	if err != nil || len(tx) == 0 {
		http.Error(w, "bad tx_base64", http.StatusBadRequest)
		return
	}
	sig, err := g.gov.SubmitSigned(r.Context(), tx)
	if err != nil {
		g.governError(w, err)
		return
	}
	writeJSON(w, map[string]string{"signature": sig})
}

func (g *webGateway) governError(w http.ResponseWriter, err error) {
	g.logger.Warn("mosey web: governance", "err", err)
	http.Error(w, "governance op failed", http.StatusBadGateway)
}
