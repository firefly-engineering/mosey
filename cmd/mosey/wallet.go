// runWallet implements `mosey wallet` — interactive, browser-wallet
// operations. Today: `mosey wallet sign`, which obtains a delegation
// signature from a browser wallet (Phantom) via a loopback page.
//
// The canonical delegation content is rendered in Go (the single source
// of truth — see wallet.Fields.Render); the page only relays those
// bytes to the wallet's signMessage and posts the signature back, so
// there is no JS rendering to drift from the Go form.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/firefly-engineering/mosey/wallet"
)

func runWallet(args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "mosey wallet: missing subcommand; want: sign")
		return 2
	}
	switch args[0] {
	case "sign":
		return runWalletSign(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "mosey wallet: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runWalletSign(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("mosey wallet sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	session := fs.String("session", "", "base58 session address this grant is scoped to")
	delegate := fs.String("delegate", "", "base58 address to delegate to (e.g. a connection key or a viewer wallet)")
	capsStr := fs.String("caps", "view-only", "caps to grant: comma-separated write,resize,forge — or view-only")
	expires := fs.Duration("expires", 24*time.Hour, "validity duration from now")
	out := fs.String("out", "grant.json", "output path for the signed delegation chain")
	noBrowser := fs.Bool("no-browser", false, "print the URL instead of opening a browser")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "mosey wallet sign:", err)
		return 2
	}
	if *session == "" || *delegate == "" {
		fmt.Fprintln(stderr, "mosey wallet sign: --session and --delegate are required")
		return 2
	}
	sessionID, err := wallet.ParseAddress(*session)
	if err != nil {
		fmt.Fprintln(stderr, "mosey wallet sign: --session:", err)
		return 2
	}
	delegatePub, err := wallet.ParseAddress(*delegate)
	if err != nil {
		fmt.Fprintln(stderr, "mosey wallet sign: --delegate:", err)
		return 2
	}
	caps, err := wallet.ParseCapsLenient(*capsStr)
	if err != nil {
		fmt.Fprintln(stderr, "mosey wallet sign: --caps:", err)
		return 2
	}

	authz, err := newAuthorizer(sessionID, delegatePub, caps, *expires)
	if err != nil {
		fmt.Fprintln(stderr, "mosey wallet sign:", err)
		return 1
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(stderr, "mosey wallet sign: listen:", err)
		return 1
	}
	url := fmt.Sprintf("http://%s/?state=%s", ln.Addr().String(), authz.state)
	srv := &http.Server{Handler: authz.mux()}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	fmt.Fprintf(stderr, "mosey wallet sign: approve in your browser at:\n  %s\n", url)
	if !*noBrowser {
		_ = openBrowser(url)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	select {
	case <-ctx.Done():
		fmt.Fprintln(stderr, "mosey wallet sign: timed out waiting for the wallet signature")
		return 1
	case res := <-authz.done:
		if res.err != nil {
			fmt.Fprintln(stderr, "mosey wallet sign:", res.err)
			return 1
		}
		if err := os.WriteFile(*out, res.chain, 0o644); err != nil {
			fmt.Fprintln(stderr, "mosey wallet sign: write:", err)
			return 1
		}
		fmt.Fprintf(stdout, "mosey wallet sign: wrote %s (signed by %s)\n", *out, res.signer)
		return 0
	}
}

// authorizer holds one pending signing request and its loopback HTTP
// handlers. The flow: GET / serves the page; POST /prepare renders the
// canonical content for the connected wallet; POST /callback verifies
// the returned signature and resolves done.
type authorizer struct {
	session  ed25519.PublicKey
	delegate ed25519.PublicKey
	caps     wallet.Caps
	expires  time.Duration
	state    string

	mu      sync.Mutex
	content []byte // canonical content rendered for the connecting wallet
	done    chan authzResult
}

type authzResult struct {
	chain  []byte
	signer string
	err    error
}

func newAuthorizer(session, delegate ed25519.PublicKey, caps wallet.Caps, expires time.Duration) (*authorizer, error) {
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("state nonce: %w", err)
	}
	return &authorizer{
		session:  session,
		delegate: delegate,
		caps:     caps,
		expires:  expires,
		state:    hex.EncodeToString(stateBytes),
		done:     make(chan authzResult, 1),
	}, nil
}

func (a *authorizer) mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/prepare", a.handlePrepare)
	mux.HandleFunc("/callback", a.handleCallback)
	return mux
}

func (a *authorizer) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(signPageHTML))
}

// prepareRequest carries the connected wallet's address; the server
// renders the canonical content with it as the delegator.
type prepareRequest struct {
	State  string `json:"state"`
	Wallet string `json:"wallet"` // base58
}

type prepareResponse struct {
	ContentHex string `json:"content_hex"`
}

func (a *authorizer) handlePrepare(w http.ResponseWriter, r *http.Request) {
	var req prepareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.State != a.state {
		http.Error(w, "bad state", http.StatusForbidden)
		return
	}
	delegator, err := wallet.ParseAddress(req.Wallet)
	if err != nil {
		http.Error(w, "bad wallet", http.StatusBadRequest)
		return
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	content := wallet.Fields{
		SessionID: a.session,
		Delegator: delegator,
		Delegate:  a.delegate,
		Caps:      a.caps,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(a.expires),
		Nonce:     nonce,
	}.Render()

	a.mu.Lock()
	a.content = content
	a.mu.Unlock()

	writeJSON(w, prepareResponse{ContentHex: hex.EncodeToString(content)})
}

// callbackRequest carries the wallet's signature over the prepared
// content, base58-encoded as signMessage returns it.
type callbackRequest struct {
	State        string `json:"state"`
	SignatureB58 string `json:"signature_base58"`
}

func (a *authorizer) handleCallback(w http.ResponseWriter, r *http.Request) {
	var req callbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.State != a.state {
		http.Error(w, "bad state", http.StatusForbidden)
		return
	}
	a.mu.Lock()
	content := a.content
	a.mu.Unlock()
	if content == nil {
		http.Error(w, "no prepared content", http.StatusConflict)
		return
	}
	sigBytes, decErr := base58Sig(req.SignatureB58)
	if decErr != nil {
		http.Error(w, "bad signature", http.StatusBadRequest)
		a.finish(authzResult{err: fmt.Errorf("decode signature: %w", decErr)})
		return
	}
	deleg := wallet.Delegation{Content: content, Signature: sigBytes}
	fields, verr := deleg.Verify()
	if verr != nil {
		http.Error(w, "signature did not verify", http.StatusBadRequest)
		a.finish(authzResult{err: fmt.Errorf("verify: %w", verr)})
		return
	}
	chain, cerr := wallet.EncodeChain([]wallet.Delegation{deleg})
	if cerr != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		a.finish(authzResult{err: cerr})
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
	a.finish(authzResult{chain: chain, signer: wallet.Address(fields.Delegator)})
}

func (a *authorizer) finish(res authzResult) {
	select {
	case a.done <- res:
	default: // already finished
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// base58Sig decodes a base58 string expected to be a 64-byte Ed25519
// signature.
func base58Sig(s string) ([]byte, error) {
	b, err := wallet.DecodeBase58(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature is %d bytes, want %d", len(b), ed25519.SignatureSize)
	}
	return b, nil
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

// signPageHTML is the minimal loopback signing page. It reads the state
// from the URL, lets the user pick an installed wallet (Phantom / Solflare
// / Backpack), asks the server to render the canonical content, signs the
// raw bytes, and posts the signature back.
const signPageHTML = `<!doctype html>
<meta charset="utf-8" />
<title>mosey · approve session grant</title>
<style>
  body { font: 14px/1.5 ui-monospace, monospace; max-width: 48rem; margin: 3rem auto; padding: 0 1rem; }
  pre { background: #f4f4f4; padding: 1rem; white-space: pre-wrap; word-break: break-all; }
  button { font: inherit; padding: .5rem 1rem; }
  .ok { color: #137333; } .err { color: #b00020; }
</style>
<h1>mosey · approve session grant</h1>
<p id="status">Connect your wallet to review and sign the delegation.</p>
<div id="wallets">Detecting wallets…</div>
<h3>Delegation</h3>
<pre id="content">—</pre>
<script type="module">
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const b58 = (bytes) => {
    let n = 0n;
    for (const b of bytes) n = n * 256n + BigInt(b);
    let o = "";
    while (n > 0n) { o = ALPHABET[Number(n % 58n)] + o; n /= 58n; }
    for (const b of bytes) { if (b !== 0) break; o = "1" + o; }
    return o || "1";
  };
  const hexToBytes = (h) => { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.slice(i*2, i*2+2), 16); return a; };
  const state = new URLSearchParams(location.search).get("state") || "";
  const status = document.getElementById("status");
  const set = (msg, cls) => { status.textContent = msg; status.className = cls || ""; };

  // Detect each wallet by its own injected global, not window.solana
  // (only one wallet can own that), so the user can pick which one signs.
  function detect() {
    const out = [], seen = new Set();
    const add = (name, p) => { if (p && !seen.has(p)) { seen.add(p); out.push({ name, p }); } };
    add("Phantom", window.phantom?.solana);
    add("Solflare", window.solflare);
    add("Backpack", window.backpack?.solana ?? (window.backpack?.isBackpack ? window.backpack : null));
    const ws = window.solana;
    if (ws && !seen.has(ws)) {
      const who = ws.isPhantom ? "Phantom" : ws.isSolflare ? "Solflare" : ws.isBackpack ? "Backpack" : "unknown";
      add(who + " (window.solana)", ws);
    }
    return out;
  }

  async function sign(provider) {
    try {
      set("Connecting…");
      const resp = await provider.connect();
      const walletAddr = (resp?.publicKey ?? provider.publicKey).toString();

      const prep = await fetch("/prepare", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ state, wallet: walletAddr }) });
      if (!prep.ok) { set("prepare failed: " + (await prep.text()), "err"); return; }
      const { content_hex } = await prep.json();
      const contentBytes = hexToBytes(content_hex);
      document.getElementById("content").textContent = new TextDecoder().decode(contentBytes);

      const res = await provider.signMessage(contentBytes, "utf8");
      const sig = res.signature ?? res;
      const cb = await fetch("/callback", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ state, signature_base58: b58(sig) }) });
      if (cb.ok) set("Signed. You can close this tab and return to the terminal.", "ok");
      else set("callback failed: " + (await cb.text()), "err");
    } catch (e) {
      set("error: " + (e?.message ?? e), "err");
    }
  }

  function renderWallets() {
    const box = document.getElementById("wallets");
    const found = detect();
    box.innerHTML = "";
    if (!found.length) { box.textContent = "No Solana wallet found (Phantom / Solflare / Backpack)."; box.className = "err"; return; }
    for (const { name, p } of found) {
      const btn = document.createElement("button");
      btn.textContent = name;
      btn.onclick = () => sign(p);
      box.appendChild(btn);
    }
  }

  // Extensions inject asynchronously; scan now and again shortly after load.
  renderWallets();
  setTimeout(renderWallets, 600);
</script>
`
