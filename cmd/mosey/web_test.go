package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/firefly-engineering/mosey/auth"
	unixbackend "github.com/firefly-engineering/mosey/transport/unix"
	"github.com/firefly-engineering/mosey/vterm"
	"github.com/firefly-engineering/mosey/wallet"
	"github.com/firefly-engineering/mosey/walletsolana"
)

// TestWebGateway_BridgeRoundTrip stands up an in-process vterm host
// running `cat` over a unix socket, points the web gateway at it, and
// drives a real browser-style WebSocket through the gateway: binary
// frames in, echoed binary frames out. Proves the browser↔gateway↔host
// bridge end to end (auth handshake, PTY pump, resize control).
func TestWebGateway_BridgeRoundTrip(t *testing.T) {
	psk, err := auth.NewPSKAuth("web-secret")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Host: vterm over a unix socket running `cat` (echoes input).
	sock := filepath.Join("/tmp", fmt.Sprintf("mosey-web-%d.sock", os.Getpid()))
	defer func() { _ = os.Remove(sock) }()
	hostBackend, err := unixbackend.New(ctx, unixbackend.Options{ListenAddr: sock})
	if err != nil {
		t.Fatalf("host backend: %v", err)
	}
	defer func() { _ = hostBackend.Close() }()
	hostAuthed := auth.Wrap(hostBackend, psk)
	hostAuthed.Serve()

	ready := make(chan struct{})
	go func() { _ = vterm.Run(ctx, vterm.Options{Transport: hostAuthed, Ready: ready}, []string{"cat"}) }()
	<-ready

	endpoints := hostBackend.Endpoints()
	if len(endpoints) == 0 {
		t.Fatal("host published no endpoints")
	}

	// Gateway: client-only unix backend wrapped with the same PSK,
	// pointed at the host endpoint.
	gwClient, err := unixbackend.New(ctx, unixbackend.Options{})
	if err != nil {
		t.Fatalf("gateway client backend: %v", err)
	}
	defer func() { _ = gwClient.Close() }()
	gw := &webGateway{
		staticTransport: auth.Wrap(gwClient, psk),
		target:          endpoints[0],
		logger:          newLogger(os.Stderr, "error"),
		logins:          map[string]*loginSession{},
	}

	srv := httptest.NewServer(gw.mux())
	defer srv.Close()

	// The static page is served.
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "mosey · web terminal") {
		t.Fatalf("GET / = %d, body lacks title: %.80q", resp.StatusCode, body)
	}

	// Browser-style WebSocket to /ws.
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Accumulate output frames in the background.
	var mu sync.Mutex
	var out strings.Builder
	go func() {
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.BinaryMessage {
				mu.Lock()
				out.Write(data)
				mu.Unlock()
			}
		}
	}()

	// Resize (text control), then input (binary).
	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","cols":80,"rows":24}`)); err != nil {
		t.Fatalf("ws resize: %v", err)
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("hello-web\n")); err != nil {
		t.Fatalf("ws write: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := out.String()
		mu.Unlock()
		if strings.Contains(got, "hello-web") {
			return // success
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	got := out.String()
	mu.Unlock()
	t.Fatalf("did not observe echoed input; got %.200q", got)
}

// TestWebGateway_WalletLoginRoundTrip exercises the --wallet-login flow
// end to end with a local key standing in for the browser wallet: the
// gateway mints K and renders the W→K delegation (prepare), the "wallet"
// signs the canonical content (signMessage), the gateway verifies it
// (callback) and attaches to a wallet-auth host with that delegation.
func TestWebGateway_WalletLoginRoundTrip(t *testing.T) {
	mkKey := func() ed25519.PrivateKey {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("gen key: %v", err)
		}
		return k
	}
	pub := func(p ed25519.PrivateKey) ed25519.PublicKey { return p.Public().(ed25519.PublicKey) }

	session := mkKey()
	sessionID := pub(session)
	owner := mkKey() // stands in for the browser wallet W

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Wallet-auth host: W owns the session; runs `cat`.
	src := wallet.NewMemSource(wallet.NewMemSnapshot(pub(owner)))
	serverAuth, err := auth.NewWalletServerAuth(auth.ServerOptions{SessionKey: session, Source: src})
	if err != nil {
		t.Fatalf("server auth: %v", err)
	}
	sock := filepath.Join("/tmp", fmt.Sprintf("mosey-web-wl-%d.sock", os.Getpid()))
	defer func() { _ = os.Remove(sock) }()
	hostBackend, err := unixbackend.New(ctx, unixbackend.Options{ListenAddr: sock})
	if err != nil {
		t.Fatalf("host backend: %v", err)
	}
	defer func() { _ = hostBackend.Close() }()
	hostAuthed := auth.Wrap(hostBackend, serverAuth)
	hostAuthed.Serve()
	ready := make(chan struct{})
	go func() { _ = vterm.Run(ctx, vterm.Options{Transport: hostAuthed, Ready: ready}, []string{"cat"}) }()
	<-ready
	endpoints := hostBackend.Endpoints()
	if len(endpoints) == 0 {
		t.Fatal("host published no endpoints")
	}

	// Gateway in wallet-login mode: raw (unwrapped) client transport,
	// session = the host's session key.
	gwClient, err := unixbackend.New(ctx, unixbackend.Options{})
	if err != nil {
		t.Fatalf("gateway client backend: %v", err)
	}
	defer func() { _ = gwClient.Close() }()
	gw := &webGateway{
		raw:           gwClient,
		walletLogin:   true,
		sessionKey:    sessionID,
		delegationTTL: time.Hour,
		target:        endpoints[0],
		logger:        newLogger(os.Stderr, "error"),
		logins:        map[string]*loginSession{},
	}
	srv := httptest.NewServer(gw.mux())
	defer srv.Close()

	postJSON := func(path string, body any) map[string]string {
		buf, _ := json.Marshal(body)
		resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("POST %s = %d: %s", path, resp.StatusCode, b)
		}
		var out map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	// /config reports wallet mode + the session.
	cfgResp, err := http.Get(srv.URL + "/config")
	if err != nil {
		t.Fatalf("GET /config: %v", err)
	}
	var cfg map[string]string
	_ = json.NewDecoder(cfgResp.Body).Decode(&cfg)
	_ = cfgResp.Body.Close()
	if cfg["mode"] != "wallet" || cfg["session"] != wallet.Address(sessionID) {
		t.Fatalf("/config = %v, want wallet mode + session %s", cfg, wallet.Address(sessionID))
	}

	// Browser: prepare → sign → callback.
	prep := postJSON("/login/prepare", map[string]string{
		"wallet": wallet.Address(pub(owner)),
		"caps":   "write, resize",
	})
	content, err := hex.DecodeString(prep["content_hex"])
	if err != nil || len(content) == 0 {
		t.Fatalf("bad content_hex: %v", err)
	}
	sig := ed25519.Sign(owner, content)
	cb := postJSON("/login/callback", map[string]string{
		"token":            prep["token"],
		"signature_base58": wallet.EncodeBase58(sig),
	})
	if cb["status"] != "ok" {
		t.Fatalf("callback status = %q", cb["status"])
	}

	// Attach over the authorized WS.
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?token=" + prep["token"]
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var mu sync.Mutex
	var out strings.Builder
	go func() {
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.BinaryMessage {
				mu.Lock()
				out.Write(data)
				mu.Unlock()
			}
		}
	}()
	_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"resize","cols":80,"rows":24}`))
	if err := conn.WriteMessage(websocket.BinaryMessage, []byte("hello-wallet\n")); err != nil {
		t.Fatalf("ws write: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := out.String()
		mu.Unlock()
		if strings.Contains(got, "hello-wallet") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("did not observe echoed input over the wallet-login session")
}

// TestSessionTarget checks the session_key → /p2p/<peer-id> conversion
// round-trips to the same peer id libp2p derives from the key.
func TestSessionTarget(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	target, err := sessionTarget(pub)
	if err != nil {
		t.Fatalf("sessionTarget: %v", err)
	}
	if !strings.HasPrefix(target, "/p2p/") {
		t.Fatalf("target %q lacks /p2p/ prefix", target)
	}
	got, err := peer.Decode(strings.TrimPrefix(target, "/p2p/"))
	if err != nil {
		t.Fatalf("decode peer id: %v", err)
	}
	lpk, err := ic.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		t.Fatalf("unmarshal libp2p key: %v", err)
	}
	want, err := peer.IDFromPublicKey(lpk)
	if err != nil {
		t.Fatalf("id from key: %v", err)
	}
	if got != want {
		t.Fatalf("sessionTarget peer id = %s, want %s", got, want)
	}
}

type fakeLister struct {
	sessions []walletsolana.OwnedSession
	gotOwner ed25519.PublicKey
}

func (f *fakeLister) SessionsByOwner(_ context.Context, owner ed25519.PublicKey) ([]walletsolana.OwnedSession, error) {
	f.gotOwner = owner
	return f.sessions, nil
}

// TestWebGateway_DashboardSessions checks the /sessions endpoint maps a
// wallet to its on-chain sessions via the (faked) lister.
func TestWebGateway_DashboardSessions(t *testing.T) {
	mk := func() ed25519.PublicKey {
		p, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	owner, s1 := mk(), mk()
	fl := &fakeLister{sessions: []walletsolana.OwnedSession{{SessionKey: s1, Address: "PDA1", Epoch: 5}}}
	gw := &webGateway{
		walletLogin: true,
		multiSession: true,
		lister:      fl,
		logger:      newLogger(os.Stderr, "error"),
		logins:      map[string]*loginSession{},
	}
	srv := httptest.NewServer(gw.mux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/sessions?wallet=" + wallet.Address(owner))
	if err != nil {
		t.Fatalf("GET /sessions: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /sessions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Sessions []struct {
			Session string `json:"session"`
			Address string `json:"address"`
			Epoch   int    `json:"epoch"`
		} `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !fl.gotOwner.Equal(owner) {
		t.Errorf("lister got owner %s, want %s", wallet.Address(fl.gotOwner), wallet.Address(owner))
	}
	if len(out.Sessions) != 1 || out.Sessions[0].Session != wallet.Address(s1) ||
		out.Sessions[0].Address != "PDA1" || out.Sessions[0].Epoch != 5 {
		t.Fatalf("unexpected sessions payload: %+v", out.Sessions)
	}
}

// TestWebGateway_OffchainGrant exercises the off-chain grant governance
// op: the owner signs an owner→grantee delegation in the page and the
// gateway returns the encoded chain blob.
func TestWebGateway_OffchainGrant(t *testing.T) {
	mkKey := func() ed25519.PrivateKey {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	pub := func(p ed25519.PrivateKey) ed25519.PublicKey { return p.Public().(ed25519.PublicKey) }
	session, owner, grantee := mkKey(), mkKey(), mkKey()

	gw := &webGateway{
		walletLogin: true,
		sessionKey:  pub(session),
		logger:      newLogger(os.Stderr, "error"),
		logins:      map[string]*loginSession{},
		grants:      map[string]*pendingGrant{},
	}
	srv := httptest.NewServer(gw.mux())
	defer srv.Close()

	post := func(path string, body any) map[string]string {
		buf, _ := json.Marshal(body)
		resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("POST %s = %d: %s", path, resp.StatusCode, b)
		}
		var out map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	prep := post("/grant/prepare", map[string]any{
		"wallet":          wallet.Address(pub(owner)),
		"grantee":         wallet.Address(pub(grantee)),
		"caps":            "write, resize",
		"expires_seconds": 3600,
	})
	content, err := hex.DecodeString(prep["content_hex"])
	if err != nil || len(content) == 0 {
		t.Fatalf("bad content_hex: %v", err)
	}
	sig := ed25519.Sign(owner, content)
	cb := post("/grant/callback", map[string]string{
		"token":            prep["token"],
		"signature_base58": wallet.EncodeBase58(sig),
	})
	blob, err := base64.StdEncoding.DecodeString(cb["grant_base64"])
	if err != nil {
		t.Fatalf("bad grant_base64: %v", err)
	}
	chain, err := wallet.DecodeChain(blob)
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("chain len %d, want 1", len(chain))
	}
	fields, err := chain[0].Verify()
	if err != nil {
		t.Fatalf("delegation does not verify: %v", err)
	}
	if !fields.Delegator.Equal(pub(owner)) || !fields.Delegate.Equal(pub(grantee)) {
		t.Errorf("delegator/delegate = %s/%s, want %s/%s",
			wallet.Address(fields.Delegator), wallet.Address(fields.Delegate),
			wallet.Address(pub(owner)), wallet.Address(pub(grantee)))
	}
	if !fields.SessionID.Equal(pub(session)) {
		t.Errorf("session = %s, want %s", wallet.Address(fields.SessionID), wallet.Address(pub(session)))
	}
	if fields.Caps != wallet.CapWrite|wallet.CapResize {
		t.Errorf("caps = %v, want write|resize", fields.Caps)
	}
}

type fakeGovernor struct {
	owner, session, newOwner ed25519.PublicKey
	submitted                []byte
	tx                       []byte
	sig                      string
}

func (f *fakeGovernor) BuildTransferOwnership(_ context.Context, owner, session, newOwner ed25519.PublicKey) ([]byte, error) {
	f.owner, f.session, f.newOwner = owner, session, newOwner
	return f.tx, nil
}
func (f *fakeGovernor) BuildGrant(_ context.Context, owner, session, grantee ed25519.PublicKey, caps uint8, expiry int64) ([]byte, error) {
	return f.tx, nil
}
func (f *fakeGovernor) BuildBumpEpoch(_ context.Context, owner, session ed25519.PublicKey) ([]byte, error) {
	return f.tx, nil
}
func (f *fakeGovernor) SubmitSigned(_ context.Context, tx []byte) (string, error) {
	f.submitted = tx
	return f.sig, nil
}

// TestWebGateway_Govern checks the on-chain governance endpoints route to
// the governor and pass the bytes through (browser signing is verified on
// devnet, not here).
func TestWebGateway_Govern(t *testing.T) {
	mk := func() ed25519.PublicKey {
		p, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	owner, session, newOwner := mk(), mk(), mk()
	fg := &fakeGovernor{tx: []byte("UNSIGNED-TX"), sig: "SIG123"}
	gw := &webGateway{
		walletLogin:  true,
		multiSession: true,
		gov:          fg,
		logger:       newLogger(os.Stderr, "error"),
		logins:       map[string]*loginSession{},
		grants:       map[string]*pendingGrant{},
	}
	srv := httptest.NewServer(gw.mux())
	defer srv.Close()

	post := func(path string, body any) map[string]string {
		buf, _ := json.Marshal(body)
		resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("POST %s = %d: %s", path, resp.StatusCode, b)
		}
		var out map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	build := post("/govern/build", map[string]any{
		"op":        "transfer",
		"wallet":    wallet.Address(owner),
		"session":   wallet.Address(session),
		"new_owner": wallet.Address(newOwner),
	})
	tx, err := base64.StdEncoding.DecodeString(build["tx_base64"])
	if err != nil || string(tx) != "UNSIGNED-TX" {
		t.Fatalf("build tx = %q (err %v), want UNSIGNED-TX", tx, err)
	}
	if !fg.owner.Equal(owner) || !fg.session.Equal(session) || !fg.newOwner.Equal(newOwner) {
		t.Fatal("governor received wrong transfer args")
	}

	sub := post("/govern/submit", map[string]string{
		"tx_base64": base64.StdEncoding.EncodeToString([]byte("SIGNED-TX")),
	})
	if sub["signature"] != "SIG123" {
		t.Fatalf("submit signature = %q, want SIG123", sub["signature"])
	}
	if string(fg.submitted) != "SIGNED-TX" {
		t.Fatalf("governor submitted %q, want SIGNED-TX", fg.submitted)
	}
}
