// Off-chain grant flow for `mosey web` — the governance op that needs no
// transaction. The owner picks a session, a grantee wallet, caps, and an
// expiry; signs the canonical `owner → grantee` delegation in the page
// (signMessage); and the gateway returns the encoded chain blob to hand
// to the grantee (who attaches with `mosey attach --wallet-grant`, or a
// future web import). The on-chain governance ops (transfer / grant /
// revoke / bump-epoch) need browser-signed transactions and are tracked
// separately — see docs/src/web-attach.md.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/firefly-engineering/mosey/wallet"
)

// pendingGrant holds the canonical delegation text awaiting the owner's
// signature, keyed by an opaque token.
type pendingGrant struct {
	content []byte
	expires time.Time
}

func (g *webGateway) putGrant(token string, p *pendingGrant) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.grants[token] = p
}

func (g *webGateway) takeGrant(token string) *pendingGrant {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.grants[token]
	delete(g.grants, token)
	if p == nil || time.Now().After(p.expires) {
		return nil
	}
	return p
}

// handleGrantPrepare renders the `owner → grantee` delegation the owner's
// wallet must sign. Request: {wallet, session, grantee, caps, expires_seconds}.
// Response: {token, content_hex}.
func (g *webGateway) handleGrantPrepare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Wallet         string `json:"wallet"`
		Session        string `json:"session"`
		Grantee        string `json:"grantee"`
		Caps           string `json:"caps"`
		ExpiresSeconds int64  `json:"expires_seconds"`
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
	grantee, err := wallet.ParseAddress(req.Grantee)
	if err != nil {
		http.Error(w, "bad grantee", http.StatusBadRequest)
		return
	}
	sessionKey := g.sessionKey
	if g.multiSession {
		if sessionKey, err = wallet.ParseAddress(req.Session); err != nil {
			http.Error(w, "bad or missing session", http.StatusBadRequest)
			return
		}
	}
	caps := wallet.Caps(0)
	if req.Caps != "" {
		if caps, err = wallet.ParseCapsLenient(req.Caps); err != nil {
			http.Error(w, "bad caps", http.StatusBadRequest)
			return
		}
	}
	ttl := time.Duration(req.ExpiresSeconds) * time.Second
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	content := wallet.Fields{
		SessionID: sessionKey,
		Delegator: owner,
		Delegate:  grantee,
		Caps:      caps,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(ttl),
		Nonce:     nonce,
	}.Render()

	token, err := newLoginToken()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	g.putGrant(token, &pendingGrant{content: content, expires: now.Add(time.Hour)})
	writeJSON(w, map[string]string{"token": token, "content_hex": hex.EncodeToString(content)})
}

// handleGrantCallback verifies the owner's signature and returns the
// encoded delegation chain blob. Request: {token, signature_base58}.
// Response: {grant_base64}.
func (g *webGateway) handleGrantCallback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token        string `json:"token"`
		SignatureB58 string `json:"signature_base58"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	p := g.takeGrant(req.Token)
	if p == nil {
		http.Error(w, "unknown or expired token", http.StatusForbidden)
		return
	}
	sig, err := base58Sig(req.SignatureB58)
	if err != nil {
		http.Error(w, "bad signature", http.StatusBadRequest)
		return
	}
	deleg := wallet.Delegation{Content: p.content, Signature: sig}
	if _, err := deleg.Verify(); err != nil {
		http.Error(w, "signature did not verify", http.StatusBadRequest)
		return
	}
	blob, err := wallet.EncodeChain([]wallet.Delegation{deleg})
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"grant_base64": base64.StdEncoding.EncodeToString(blob)})
}
