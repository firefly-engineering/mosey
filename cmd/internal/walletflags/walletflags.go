// Package walletflags wires the wallet/blockchain authenticator into
// the CLI. Shared by `mosey launch` (server side) and `mosey attach`
// (client side) so the flag surface is consistent.
//
// The server side currently resolves ownership/grants from an in-memory
// "dev" snapshot (--wallet-dev-owner / --wallet-dev-grant); the Solana
// SnapshotSource lands in a later phase behind --wallet-program /
// --wallet-rpc.
package walletflags

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/wallet"
	"github.com/firefly-engineering/mosey/walletsolana"
)

// ServerFlags is the listener-side bundle (`mosey launch`).
type ServerFlags struct {
	SessionKeyPath string
	// On-chain source (Solana).
	Program      string
	RPC          string
	MaxStaleness time.Duration
	Commitment   string
	// In-memory dev stub (no chain).
	DevOwner  string   // base58 owner address
	DevGrants []string // repeatable "address=caps" grants
}

// Register binds the server flags to fs.
func (f *ServerFlags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.SessionKeyPath, "wallet-session-key", "",
		"path to the persisted Ed25519 session key (the on-chain session identity); created if absent. Enables wallet auth.")
	fs.StringVar(&f.Program, "wallet-program", "",
		"base58 program id of the mosey-session program (with --wallet-rpc, resolves ownership/grants on-chain)")
	fs.StringVar(&f.RPC, "wallet-rpc", "",
		"Solana JSON-RPC endpoint (e.g. https://api.devnet.solana.com)")
	fs.DurationVar(&f.MaxStaleness, "wallet-max-staleness", 0,
		"fail-open budget: serve the last snapshot up to this long during RPC trouble (default 30s)")
	fs.StringVar(&f.Commitment, "wallet-commitment", "",
		"Solana commitment for reads/subscriptions (default confirmed)")
	fs.StringVar(&f.DevOwner, "wallet-dev-owner", "",
		"base58 wallet address treated as the session owner, via an in-memory snapshot (dev/testing; no chain)")
	fs.Var((*sliceFlag)(&f.DevGrants), "wallet-dev-grant",
		"in-memory grant `address=caps` (caps: comma-separated write,resize,forge or view-only); repeatable")
}

// Configured reports whether wallet auth was selected.
func (f *ServerFlags) Configured() bool { return f.SessionKeyPath != "" }

// SessionPublic loads (creating if absent) the session key and returns
// its public half — the base58 session id the chain registers and that
// clients name via `mosey attach --wallet-session` / `mosey web --session`.
func (f *ServerFlags) SessionPublic() (ed25519.PublicKey, error) {
	key, err := loadOrCreateKey(f.SessionKeyPath)
	if err != nil {
		return nil, err
	}
	return key.Public().(ed25519.PublicKey), nil
}

// Build resolves the server-side wallet authenticator.
func (f *ServerFlags) Build() (*auth.WalletAuth, error) {
	if !f.Configured() {
		return nil, errors.New("walletflags: --wallet-session-key required for wallet auth")
	}
	key, err := loadOrCreateKey(f.SessionKeyPath)
	if err != nil {
		return nil, fmt.Errorf("walletflags: --wallet-session-key: %w", err)
	}

	if f.Program != "" {
		return f.buildChain(key)
	}

	// In-memory dev stub.
	if f.DevOwner == "" {
		return nil, errors.New("walletflags: set --wallet-program (+ --wallet-rpc) for on-chain auth, or --wallet-dev-owner for the in-memory stub")
	}
	owner, err := wallet.ParseAddress(f.DevOwner)
	if err != nil {
		return nil, fmt.Errorf("walletflags: --wallet-dev-owner: %w", err)
	}
	snap := wallet.NewMemSnapshot(owner)
	for _, g := range f.DevGrants {
		addr, caps, err := parseGrant(g)
		if err != nil {
			return nil, fmt.Errorf("walletflags: --wallet-dev-grant: %w", err)
		}
		snap.WithGrant(addr, caps)
	}
	return auth.NewWalletServerAuth(auth.ServerOptions{
		SessionKey: key,
		Source:     wallet.NewMemSource(snap),
	})
}

// buildChain wires the Solana-backed snapshot source: it loads an
// initial snapshot synchronously (so misconfiguration fails fast at
// launch) and starts a background poll for the process lifetime.
func (f *ServerFlags) buildChain(key ed25519.PrivateKey) (*auth.WalletAuth, error) {
	if f.RPC == "" {
		return nil, errors.New("walletflags: --wallet-rpc is required with --wallet-program")
	}
	src, err := walletsolana.New(walletsolana.Options{
		RPCEndpoint:  f.RPC,
		ProgramID:    f.Program,
		SessionKey:   key.Public().(ed25519.PublicKey),
		MaxStaleness: f.MaxStaleness,
		Commitment:   f.Commitment,
	})
	if err != nil {
		return nil, fmt.Errorf("walletflags: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	err = src.Refresh(ctx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("walletflags: initial snapshot: %w", err)
	}
	go src.Run(context.Background(), nil)
	return auth.NewWalletServerAuth(auth.ServerOptions{SessionKey: key, Source: src})
}

// ClientFlags is the dialer-side bundle (`mosey attach`).
type ClientFlags struct {
	ConnKeyPath string // ephemeral connection key K_c; generated if absent
	GrantPath   string // delegation chain blob (see wallet.EncodeChain)
	Session     string // base58 expected session identity (MITM protection)
}

// Register binds the client flags to fs.
func (f *ClientFlags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.GrantPath, "wallet-grant", "",
		"path to a delegation chain blob authorizing this client (from `mosey grant`). Enables wallet auth.")
	fs.StringVar(&f.ConnKeyPath, "wallet-conn-key", "",
		"path to the Ed25519 connection key the grant delegates to; generated ephemerally if absent")
	fs.StringVar(&f.Session, "wallet-session", "",
		"base58 session address this client expects to reach; the handshake fails if the server proves a different one")
}

// Configured reports whether wallet auth was selected.
func (f *ClientFlags) Configured() bool { return f.GrantPath != "" || f.ConnKeyPath != "" }

// Build resolves the client-side wallet authenticator.
func (f *ClientFlags) Build() (*auth.WalletAuth, error) {
	if f.GrantPath == "" {
		return nil, errors.New("walletflags: --wallet-grant required for wallet auth")
	}
	blob, err := os.ReadFile(f.GrantPath)
	if err != nil {
		return nil, fmt.Errorf("walletflags: --wallet-grant: %w", err)
	}
	chain, err := wallet.DecodeChain(blob)
	if err != nil {
		return nil, fmt.Errorf("walletflags: --wallet-grant: %w", err)
	}

	var connKey ed25519.PrivateKey
	if f.ConnKeyPath != "" {
		connKey, err = loadOrCreateKey(f.ConnKeyPath)
		if err != nil {
			return nil, fmt.Errorf("walletflags: --wallet-conn-key: %w", err)
		}
	} else {
		if _, connKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, fmt.Errorf("walletflags: generate connection key: %w", err)
		}
	}

	var expect ed25519.PublicKey
	if f.Session != "" {
		if expect, err = wallet.ParseAddress(f.Session); err != nil {
			return nil, fmt.Errorf("walletflags: --wallet-session: %w", err)
		}
	}

	return auth.NewWalletClientAuth(auth.ClientOptions{
		ConnKey:       connKey,
		Chain:         chain,
		ExpectSession: expect,
	})
}

// loadOrCreateKey reads a hex-encoded Ed25519 private key from path, or
// generates and persists one (0600) if the file does not exist.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		dec, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("hex decode: %w", err)
		}
		if len(dec) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("decoded length %d, want %d", len(dec), ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(dec), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

func parseGrant(s string) (ed25519.PublicKey, wallet.Caps, error) {
	addr, capsStr, ok := strings.Cut(s, "=")
	if !ok {
		return nil, 0, fmt.Errorf("grant %q is not address=caps", s)
	}
	pub, err := wallet.ParseAddress(addr)
	if err != nil {
		return nil, 0, err
	}
	caps, err := wallet.ParseCaps(capsStr)
	if err != nil {
		return nil, 0, err
	}
	return pub, caps, nil
}

// sliceFlag accumulates repeated flag values.
type sliceFlag []string

func (s *sliceFlag) Set(v string) error { *s = append(*s, v); return nil }
func (s *sliceFlag) String() string     { return strings.Join(*s, ",") }
