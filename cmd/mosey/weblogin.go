// Wallet-login flow for `mosey web` (--wallet-login). Each browser
// proves its wallet W and signs a fresh W→K delegation in the page; the
// gateway mints the ephemeral connection key K, verifies the signature,
// and attaches to the host with that user's on-chain access. This is the
// inline, loopback-less form of `mosey wallet sign` + `mosey attach
// --wallet-grant`: the wallet and the attach client share the page.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/transport"
	"github.com/firefly-engineering/mosey/wallet"
)

// loginSession is one in-flight or completed browser wallet login,
// keyed by an opaque token. content is the canonical delegation text the
// wallet signs; authed is the per-user transport, set once the signature
// verifies (nil until then).
type loginSession struct {
	connKey    ed25519.PrivateKey
	content    []byte
	sessionKey ed25519.PublicKey   // the session this login attaches to
	target     string              // dial string for that session
	authed     transport.Transport // set once the signature verifies
	expires    time.Time
}

func (g *webGateway) putLogin(token string, ls *loginSession) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.logins[token] = ls
}

// getLogin returns the (non-expired) login for token, or nil. Expired
// entries are dropped lazily.
func (g *webGateway) getLogin(token string) *loginSession {
	g.mu.Lock()
	defer g.mu.Unlock()
	ls := g.logins[token]
	if ls == nil {
		return nil
	}
	if time.Now().After(ls.expires) {
		delete(g.logins, token)
		return nil
	}
	return ls
}

func (g *webGateway) authorizeLogin(token string, authed transport.Transport) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ls := g.logins[token]; ls != nil {
		ls.authed = authed
	}
}

func newLoginToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// handleLoginPrepare mints K and renders the W→K delegation content the
// browser wallet must sign. Request: {wallet, caps}. Response:
// {token, content_hex}.
func (g *webGateway) handleLoginPrepare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Wallet  string `json:"wallet"`
		Caps    string `json:"caps"`
		Session string `json:"session"` // multi-session mode: which session to attach
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	delegator, err := wallet.ParseAddress(req.Wallet)
	if err != nil {
		http.Error(w, "bad wallet", http.StatusBadRequest)
		return
	}

	// Resolve which session this login attaches to. In multi-session mode
	// the browser names it (from the dashboard); otherwise it is the
	// gateway's fixed --session / --target.
	sessionKey, target := g.sessionKey, g.target
	if g.multiSession {
		if sessionKey, err = wallet.ParseAddress(req.Session); err != nil {
			http.Error(w, "bad or missing session", http.StatusBadRequest)
			return
		}
		if target, err = sessionTarget(sessionKey); err != nil {
			http.Error(w, "bad session key", http.StatusBadRequest)
			return
		}
	}
	caps := wallet.Caps(0) // view-only default
	if req.Caps != "" {
		if caps, err = wallet.ParseCaps(req.Caps); err != nil {
			http.Error(w, "bad caps", http.StatusBadRequest)
			return
		}
	}
	caps &^= wallet.CapForge // the gateway key never gets forge

	connPub, connKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	content := wallet.Fields{
		SessionID: sessionKey,
		Delegator: delegator,
		Delegate:  connPub,
		Caps:      caps,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(g.delegationTTL),
		Nonce:     nonce,
	}.Render()

	token, err := newLoginToken()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	g.putLogin(token, &loginSession{
		connKey:    connKey,
		content:    content,
		sessionKey: sessionKey,
		target:     target,
		expires:    now.Add(g.delegationTTL),
	})
	writeJSON(w, map[string]string{"token": token, "content_hex": hex.EncodeToString(content)})
}

// handleLoginCallback verifies the wallet's signature over the prepared
// content and builds the per-login authenticator. Request:
// {token, signature_base58}.
func (g *webGateway) handleLoginCallback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token        string `json:"token"`
		SignatureB58 string `json:"signature_base58"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ls := g.getLogin(req.Token)
	if ls == nil {
		http.Error(w, "unknown or expired token", http.StatusForbidden)
		return
	}
	sig, err := base58Sig(req.SignatureB58)
	if err != nil {
		http.Error(w, "bad signature", http.StatusBadRequest)
		return
	}
	deleg := wallet.Delegation{Content: ls.content, Signature: sig}
	if _, err := deleg.Verify(); err != nil {
		http.Error(w, "signature did not verify", http.StatusBadRequest)
		return
	}
	clientAuth, err := auth.NewWalletClientAuth(auth.ClientOptions{
		ConnKey:       ls.connKey,
		Chain:         []wallet.Delegation{deleg},
		ExpectSession: ls.sessionKey,
	})
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	g.authorizeLogin(req.Token, auth.Wrap(g.raw, clientAuth))
	writeJSON(w, map[string]string{"status": "ok"})
}
