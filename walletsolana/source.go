package walletsolana

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/firefly-engineering/mosey/wallet"
)

// Caller performs one JSON-RPC call. It is the injection point for the
// node connection: tests (in this package or any other) can drive the
// account-layout wiring — PDA derivation, message compilation, the
// getProgramAccounts decode — without a live node. nil means "dial the
// RPCEndpoint over HTTP".
type Caller func(ctx context.Context, method string, params []any) (json.RawMessage, error)

// errNoSession is returned by the read path (Snapshot/VerifyNow/Refresh)
// when the Source was constructed without a SessionKey. Write and
// dashboard callers (Build*, SubmitSigned, the local signers,
// SessionsByOwner) pass the session per call and never hit this.
var errNoSession = errors.New("walletsolana: no SessionKey configured; this Source is write/dashboard-only")

// Options configures a Source.
type Options struct {
	RPCEndpoint  string            // e.g. https://api.devnet.solana.com
	WSEndpoint   string            // override; default derives ws(s):// from RPCEndpoint
	ProgramID    string            // base58 program id
	SessionKey   ed25519.PublicKey // the session this server hosts; omit for write/dashboard-only use
	MaxStaleness time.Duration     // fail-open budget (default 30s)
	PollInterval time.Duration     // backstop poll (default 10s)
	Commitment   string            // default "confirmed"
	Now          func() time.Time  // default time.Now
	Call         Caller            // node connection / test injection; nil → HTTP(RPCEndpoint)
	dialWS       wsDialer          // test injection; nil → gorilla dial of WSEndpoint
}

// Source is a Solana-backed wallet.SnapshotSource. The hot path reads
// the cached snapshot; Refresh/Run keep it current via getProgramAccounts,
// with an accountSubscribe push for fast revocation (see subscribe.go).
type Source struct {
	programID         string
	sessionKey        ed25519.PublicKey
	maxStaleness      time.Duration
	pollInterval      time.Duration
	reconcileInterval time.Duration
	commitment        string
	now               func() time.Time
	call              Caller
	wsEndpoint        string
	dialWS            wsDialer

	mu       sync.Mutex
	snap     *snapshot
	lastOK   time.Time
	subAddrs []string // session account + known grant accounts, for accountSubscribe
}

// New builds a Source. It does not perform I/O — call Refresh (or Run)
// to populate the snapshot.
func New(opts Options) (*Source, error) {
	if opts.ProgramID == "" {
		return nil, errors.New("walletsolana: ProgramID required")
	}
	// SessionKey is the read path's input (which session to watch); write
	// and dashboard callers omit it. Validate it only when present — a
	// malformed key still fails fast — and defer the "missing" case to the
	// read methods, which return errNoSession.
	if len(opts.SessionKey) != 0 && len(opts.SessionKey) != ed25519.PublicKeySize {
		return nil, errors.New("walletsolana: SessionKey must be a 32-byte public key")
	}
	s := &Source{
		programID:         opts.ProgramID,
		sessionKey:        opts.SessionKey,
		maxStaleness:      orDur(opts.MaxStaleness, 30*time.Second),
		pollInterval:      orDur(opts.PollInterval, 10*time.Second),
		reconcileInterval: orDur(opts.PollInterval, 10*time.Second),
		commitment:        orStr(opts.Commitment, "confirmed"),
		now:               opts.Now,
		call:              opts.Call,
		wsEndpoint:        opts.WSEndpoint,
		dialWS:            opts.dialWS,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.call == nil {
		if opts.RPCEndpoint == "" {
			return nil, errors.New("walletsolana: RPCEndpoint required")
		}
		s.call = httpCaller(opts.RPCEndpoint)
	}
	// Push path: default the WS endpoint from the RPC URL and the dialer
	// to gorilla. Left nil (push disabled, poll-only) when neither a WS
	// endpoint nor an RPC URL to derive one from is available — e.g. unit
	// tests that inject Call directly.
	if s.wsEndpoint == "" && opts.RPCEndpoint != "" {
		s.wsEndpoint = deriveWSEndpoint(opts.RPCEndpoint)
	}
	if s.dialWS == nil && s.wsEndpoint != "" {
		s.dialWS = dialGorilla
	}
	return s, nil
}

// Snapshot implements wallet.SnapshotSource. fresh is false once the
// cached snapshot is older than MaxStaleness; err is non-nil only before
// the first successful refresh (cold start).
func (s *Source) Snapshot() (wallet.Snapshot, bool, error) {
	if len(s.sessionKey) == 0 {
		return nil, false, errNoSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap == nil {
		return nil, false, errors.New("walletsolana: no snapshot yet (cold start)")
	}
	fresh := s.now().Sub(s.lastOK) <= s.maxStaleness
	return s.snap, fresh, nil
}

// VerifyNow implements wallet.SnapshotSource: a blocking authoritative
// refresh + lookup, used on a cache miss.
func (s *Source) VerifyNow(ctx context.Context, w ed25519.PublicKey) (wallet.Caps, bool, error) {
	if err := s.Refresh(ctx); err != nil {
		return 0, false, err
	}
	s.mu.Lock()
	snap := s.snap
	s.mu.Unlock()
	caps, ok := snap.GrantCaps(w)
	return caps, ok, nil
}

// Run keeps the snapshot current until ctx is cancelled: a backstop poll
// every PollInterval, plus (when a WS endpoint is configured) an
// accountSubscribe watcher that triggers an immediate refresh on a change
// to the session or a known grant — fast revocation. Errors go to the
// optional onError callback; the snapshot keeps serving (fail-open).
func (s *Source) Run(ctx context.Context, onError func(error)) {
	refreshNow := make(chan struct{}, 1)
	if s.dialWS != nil {
		go s.watch(ctx, refreshNow, onError)
	}
	t := time.NewTicker(s.pollInterval)
	defer t.Stop()
	for {
		if err := s.Refresh(ctx); err != nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-refreshNow:
		}
	}
}

// subscribeTargets returns the current accountSubscribe set (session
// account + known grant accounts), as recorded by the last Refresh.
func (s *Source) subscribeTargets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.subAddrs...)
}

type rpcAccount struct {
	Pubkey  string `json:"pubkey"`
	Account struct {
		Data []string `json:"data"` // [base64, "base64"]
	} `json:"account"`
}

// Refresh fetches the program's accounts, finds this session and its
// live grants, and swaps in a fresh snapshot.
func (s *Source) Refresh(ctx context.Context) error {
	if len(s.sessionKey) == 0 {
		return errNoSession
	}
	raw, err := s.call(ctx, "getProgramAccounts", []any{
		s.programID,
		map[string]any{"encoding": "base64", "commitment": s.commitment},
	})
	if err != nil {
		return err
	}
	var accounts []rpcAccount
	if err := json.Unmarshal(raw, &accounts); err != nil {
		return fmt.Errorf("walletsolana: decode getProgramAccounts: %w", err)
	}

	decoded := make(map[string][]byte, len(accounts)) // pubkey -> data
	for _, a := range accounts {
		if len(a.Account.Data) == 0 {
			continue
		}
		data, derr := base64.StdEncoding.DecodeString(a.Account.Data[0])
		if derr != nil {
			continue
		}
		decoded[a.Pubkey] = data
	}

	// Find our session and its on-chain account address.
	var sess *Session
	var sessAddr ed25519.PublicKey
	var sessAddrStr string
	for pubkey, data := range decoded {
		if len(data) < 8 || [8]byte(data[:8]) != sessionDisc {
			continue
		}
		dec, derr := decodeSession(data)
		if derr != nil || !dec.SessionKey.Equal(s.sessionKey) {
			continue
		}
		addr, aerr := wallet.ParseAddress(pubkey)
		if aerr != nil {
			continue
		}
		sess, sessAddr, sessAddrStr = dec, addr, pubkey
		break
	}
	if sess == nil {
		return fmt.Errorf("walletsolana: session %s not registered under program %s", wallet.Address(s.sessionKey), s.programID)
	}

	// Collect grants that reference this session's account address, and
	// their on-chain addresses (the accountSubscribe targets for revoke).
	var grants []*Grant
	targets := []string{sessAddrStr}
	for pubkey, data := range decoded {
		if len(data) < 8 || [8]byte(data[:8]) != grantDisc {
			continue
		}
		g, gerr := decodeGrant(data)
		if gerr != nil || !g.Session.Equal(sessAddr) {
			continue
		}
		grants = append(grants, g)
		targets = append(targets, pubkey)
	}

	snap := buildSnapshot(sess, grants, s.now())
	s.mu.Lock()
	s.snap, s.lastOK, s.subAddrs = snap, s.now(), targets
	s.mu.Unlock()
	return nil
}

func httpCaller(endpoint string) Caller {
	client := &http.Client{Timeout: 15 * time.Second}
	return func(ctx context.Context, method string, params []any) (json.RawMessage, error) {
		body, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
		})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var out struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return nil, fmt.Errorf("walletsolana: decode rpc response: %w", err)
		}
		if out.Error != nil {
			return nil, fmt.Errorf("walletsolana: rpc %s: %d %s", method, out.Error.Code, out.Error.Message)
		}
		return out.Result, nil
	}
}

func orDur(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}

func orStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
