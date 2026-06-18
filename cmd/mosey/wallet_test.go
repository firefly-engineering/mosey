package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/wallet"
)

// TestAuthorizerFlow drives the loopback /prepare + /callback handlers
// the way the browser page does — connect (prepare), sign the rendered
// content, post the signature — but signs in-process (standing in for
// Phantom). The resulting grant must attach successfully.
func TestAuthorizerFlow(t *testing.T) {
	walletPub, walletPriv := genKey(t)
	sessionPub, sessionPriv := genKey(t)
	connPub, connPriv := genKey(t)

	authz, err := newAuthorizer(sessionPub, connPub, wallet.CapWrite, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(authz.mux())
	defer srv.Close()
	c := srv.Client()

	// index serves the page.
	resp, err := c.Get(srv.URL + "/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: %v status=%v", err, resp.StatusCode)
	}

	// prepare → canonical content rendered for the connecting wallet.
	contentHex := post[prepareResponse](t, c, srv.URL+"/prepare", prepareRequest{
		State: authz.state, Wallet: wallet.Address(walletPub),
	}).ContentHex
	content, err := hex.DecodeString(contentHex)
	if err != nil {
		t.Fatal(err)
	}

	// The wallet signs the raw content (Phantom signMessage analog).
	sig := ed25519.Sign(walletPriv, content)

	// callback → server verifies, resolves done.
	post[map[string]string](t, c, srv.URL+"/callback", callbackRequest{
		State: authz.state, SignatureB58: wallet.EncodeBase58(sig),
	})

	res := <-authz.done
	if res.err != nil {
		t.Fatalf("authorizer error: %v", res.err)
	}
	if res.signer != wallet.Address(walletPub) {
		t.Errorf("signer = %q, want %q", res.signer, wallet.Address(walletPub))
	}

	// The produced chain must attach (write cap, granted by walletPub
	// who the server treats as a forge-capable grantee).
	chain, err := wallet.DecodeChain(res.chain)
	if err != nil {
		t.Fatal(err)
	}
	server, _ := auth.NewWalletServerAuth(auth.ServerOptions{
		SessionKey: sessionPriv,
		Source:     wallet.NewMemSource(wallet.NewMemSnapshot(walletPub)), // walletPub is the owner here
	})
	client, _ := auth.NewWalletClientAuth(auth.ClientOptions{
		ConnKey: connPriv, Chain: chain, ExpectSession: sessionPub,
	})
	srvID, srvErr, cliErr := grantHandshake(server, client)
	if srvErr != nil || cliErr != nil {
		t.Fatalf("handshake: server=%v client=%v", srvErr, cliErr)
	}
	if !srvID.CanWrite() {
		t.Errorf("caps = %+v, want write", srvID.Caps)
	}
}

func TestAuthorizerRejectsBadState(t *testing.T) {
	walletPub, _ := genKey(t)
	sessionPub, _ := genKey(t)
	connPub, _ := genKey(t)
	authz, _ := newAuthorizer(sessionPub, connPub, wallet.CapWrite, time.Hour)
	srv := httptest.NewServer(authz.mux())
	defer srv.Close()

	body, _ := json.Marshal(prepareRequest{State: "wrong", Wallet: wallet.Address(walletPub)})
	resp, err := srv.Client().Post(srv.URL+"/prepare", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("prepare with bad state: status %d, want 403", resp.StatusCode)
	}
}

func TestAuthorizerRejectsBadSignature(t *testing.T) {
	walletPub, _ := genKey(t)
	sessionPub, _ := genKey(t)
	connPub, _ := genKey(t)
	authz, _ := newAuthorizer(sessionPub, connPub, wallet.CapWrite, time.Hour)
	srv := httptest.NewServer(authz.mux())
	defer srv.Close()
	c := srv.Client()

	post[prepareResponse](t, c, srv.URL+"/prepare", prepareRequest{State: authz.state, Wallet: wallet.Address(walletPub)})

	// A signature by the wrong key must be rejected.
	bogus := make([]byte, ed25519.SignatureSize)
	_, _ = rand.Read(bogus)
	body, _ := json.Marshal(callbackRequest{State: authz.state, SignatureB58: wallet.EncodeBase58(bogus)})
	resp, err := c.Post(srv.URL+"/callback", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusOK {
		t.Error("callback accepted a bogus signature")
	}
}

// post sends v as JSON and decodes the JSON response into T.
func post[T any](t *testing.T, c *http.Client, url string, v any) T {
	t.Helper()
	body, _ := json.Marshal(v)
	resp, err := c.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: status %d", url, resp.StatusCode)
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return out
}
