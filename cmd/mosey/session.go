// runSession implements `mosey session` — the on-chain side of wallet
// auth, mirroring the mosey-session program's owner-only instructions:
//
//	mosey session register   --wallet-session-key K.hex [flags]
//	mosey session transfer    --session ADDR --new-owner ADDR [flags]
//	mosey session bump-epoch  --session ADDR [flags]
//	mosey session grant       --session ADDR --to ADDR --caps ... [flags]
//
// These are thin wrappers over walletsolana's hand-rolled transaction
// builder: they load the owner's Solana keypair (fee payer + authority),
// resolve the session identity, submit one transaction, and print its
// signature. The off-chain `mosey grant` stays separate — it signs a
// delegation blob and never touches the chain.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/firefly-engineering/mosey/wallet"
	"github.com/firefly-engineering/mosey/walletsolana"
)

func runSession(args []string, stdout, stderr *os.File) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, sessionUsage)
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "register":
		return runSessionRegister(rest, stdout, stderr)
	case "transfer":
		return runSessionTransfer(rest, stdout, stderr)
	case "bump-epoch":
		return runSessionBumpEpoch(rest, stdout, stderr)
	case "grant":
		return runSessionGrant(rest, stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, sessionUsage)
		return 0
	default:
		fmt.Fprintf(stderr, "mosey session: unknown subcommand %q\n%s\n", sub, sessionUsage)
		return 2
	}
}

const sessionUsage = `mosey session — on-chain session ownership + grants

Usage:
  mosey session register   --wallet-session-key K.hex [flags]   register a session on-chain (owner = --keypair wallet)
  mosey session transfer    --session KEY --new-owner ADDR [flags]
  mosey session bump-epoch  --session KEY [flags]               mass-revoke: invalidate all current grants
  mosey session grant       --session KEY --to ADDR --caps ... [flags]   mint an on-chain grant

Common flags (env defaults in parentheses):
  --keypair PATH        owner Solana keypair, JSON array — fee payer & authority ($SOLANA_KEYPAIR)
  --rpc URL             Solana JSON-RPC endpoint ($SOLANA_RPC_URL, else devnet)
  --program ID          base58 mosey-session program id ($MOSEY_DEVNET_PROGRAM)
  --session KEY         base58 session identity (the key printed by "register" / used by "attach")
  --wallet-session-key PATH   hex session key file (same as "mosey launch"); an alternative to --session`

// onchainConfig holds the flags every session subcommand shares.
type onchainConfig struct {
	keypair    string
	sessionKey string // hex session key path
	session    string // base58 session key (pubkey) alternative
	rpc        string
	program    string
}

func (c *onchainConfig) register(fs *flag.FlagSet, withSessionFlag bool) {
	fs.StringVar(&c.keypair, "keypair", os.Getenv("SOLANA_KEYPAIR"),
		"owner Solana keypair (JSON array): fee payer & authority. Default $SOLANA_KEYPAIR")
	fs.StringVar(&c.rpc, "rpc", envOr("SOLANA_RPC_URL", "https://api.devnet.solana.com"),
		"Solana JSON-RPC endpoint. Default $SOLANA_RPC_URL")
	fs.StringVar(&c.program, "program", os.Getenv("MOSEY_DEVNET_PROGRAM"),
		"base58 mosey-session program id. Default $MOSEY_DEVNET_PROGRAM")
	fs.StringVar(&c.sessionKey, "wallet-session-key", "",
		"path to the hex Ed25519 session key (same file as `mosey launch`); used for its public key")
	if withSessionFlag {
		fs.StringVar(&c.session, "session", "",
			"base58 session key (public) — alternative to --wallet-session-key")
	}
}

// owner loads the owner Solana keypair and a Source bound to sessionPub.
func (c *onchainConfig) source(sessionPub ed25519.PublicKey) (*walletsolana.Source, error) {
	if c.program == "" {
		return nil, errors.New("--program is required (or set $MOSEY_DEVNET_PROGRAM)")
	}
	return walletsolana.New(walletsolana.Options{
		RPCEndpoint: c.rpc,
		ProgramID:   c.program,
		SessionKey:  sessionPub,
	})
}

// sessionPub resolves the session public key from --wallet-session-key (a
// hex private key file) or --session (a base58 public key).
func (c *onchainConfig) sessionPub() (ed25519.PublicKey, error) {
	switch {
	case c.sessionKey != "":
		k, err := loadHexKey(c.sessionKey)
		if err != nil {
			return nil, fmt.Errorf("--wallet-session-key: %w", err)
		}
		return k.Public().(ed25519.PublicKey), nil
	case c.session != "":
		pub, err := wallet.ParseAddress(c.session)
		if err != nil {
			return nil, fmt.Errorf("--session: %w", err)
		}
		return pub, nil
	default:
		return nil, errors.New("one of --session or --wallet-session-key is required")
	}
}

func runSessionRegister(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("mosey session register", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c onchainConfig
	c.register(fs, false)
	if code, done := parseOnchain(fs, args, stderr); done {
		return code
	}
	if c.sessionKey == "" {
		fmt.Fprintln(stderr, "mosey session register: --wallet-session-key is required")
		return 2
	}
	owner, code := loadOwner(c.keypair, stderr)
	if owner == nil {
		return code
	}
	sessionKey, err := loadHexKey(c.sessionKey)
	if err != nil {
		fmt.Fprintln(stderr, "mosey session register: --wallet-session-key:", err)
		return 2
	}
	src, err := c.source(sessionKey.Public().(ed25519.PublicKey))
	if err != nil {
		fmt.Fprintln(stderr, "mosey session register:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sig, err := src.RegisterSession(ctx, owner, sessionKey)
	if err != nil {
		fmt.Fprintln(stderr, "mosey session register:", err)
		return 1
	}
	sessKeyStr := wallet.Address(sessionKey.Public().(ed25519.PublicKey))
	addr, _ := src.SessionAddress(sessionKey.Public().(ed25519.PublicKey))
	fmt.Fprintf(stdout, "registered session %s\n  owner:         %s\n  account (PDA): %s\n",
		sessKeyStr, wallet.Address(owner.Public().(ed25519.PublicKey)), addr)
	printSig(stdout, c.rpc, sig)
	fmt.Fprintf(stdout, "\nThe session identity is %s — pass it to `mosey attach --wallet-session`\nand `mosey session grant --session`.\n", sessKeyStr)
	return 0
}

func runSessionTransfer(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("mosey session transfer", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c onchainConfig
	c.register(fs, true)
	newOwner := fs.String("new-owner", "", "base58 address of the new owner wallet")
	if code, done := parseOnchain(fs, args, stderr); done {
		return code
	}
	if *newOwner == "" {
		fmt.Fprintln(stderr, "mosey session transfer: --new-owner is required")
		return 2
	}
	newOwnerPub, err := wallet.ParseAddress(*newOwner)
	if err != nil {
		fmt.Fprintln(stderr, "mosey session transfer: --new-owner:", err)
		return 2
	}
	owner, sessionPub, src, code := setupOwnerSession(&c, stderr, "mosey session transfer")
	if src == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sig, err := src.TransferOwnership(ctx, owner, sessionPub, newOwnerPub)
	if err != nil {
		fmt.Fprintln(stderr, "mosey session transfer:", err)
		return 1
	}
	fmt.Fprintf(stdout, "transferred session %s ownership to %s\n", wallet.Address(sessionPub), *newOwner)
	printSig(stdout, c.rpc, sig)
	return 0
}

func runSessionBumpEpoch(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("mosey session bump-epoch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c onchainConfig
	c.register(fs, true)
	if code, done := parseOnchain(fs, args, stderr); done {
		return code
	}
	owner, sessionPub, src, code := setupOwnerSession(&c, stderr, "mosey session bump-epoch")
	if src == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sig, err := src.BumpEpoch(ctx, owner, sessionPub)
	if err != nil {
		fmt.Fprintln(stderr, "mosey session bump-epoch:", err)
		return 1
	}
	fmt.Fprintf(stdout, "bumped epoch for session %s — all current grants are now revoked\n", wallet.Address(sessionPub))
	printSig(stdout, c.rpc, sig)
	return 0
}

func runSessionGrant(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("mosey session grant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c onchainConfig
	c.register(fs, true)
	to := fs.String("to", "", "base58 grantee wallet address")
	capsStr := fs.String("caps", "view-only", "caps to grant: comma-separated write,resize,forge — or view-only")
	expires := fs.Duration("expires", 0, "validity duration from now (0 = no expiry)")
	if code, done := parseOnchain(fs, args, stderr); done {
		return code
	}
	if *to == "" {
		fmt.Fprintln(stderr, "mosey session grant: --to is required")
		return 2
	}
	grantee, err := wallet.ParseAddress(*to)
	if err != nil {
		fmt.Fprintln(stderr, "mosey session grant: --to:", err)
		return 2
	}
	caps, err := wallet.ParseCapsLenient(*capsStr)
	if err != nil {
		fmt.Fprintln(stderr, "mosey session grant: --caps:", err)
		return 2
	}
	var expiry int64
	if *expires > 0 {
		expiry = time.Now().Add(*expires).Unix()
	}
	owner, sessionPub, src, code := setupOwnerSession(&c, stderr, "mosey session grant")
	if src == nil {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sig, err := src.Grant(ctx, owner, sessionPub, grantee, uint8(caps), expiry)
	if err != nil {
		fmt.Fprintln(stderr, "mosey session grant:", err)
		return 1
	}
	exp := "no expiry"
	if expiry != 0 {
		exp = time.Unix(expiry, 0).UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(stdout, "granted %s caps=%s (%s) on session %s\n", *to, caps, exp, wallet.Address(sessionPub))
	printSig(stdout, c.rpc, sig)
	return 0
}

// setupOwnerSession resolves the owner keypair, session pubkey, and Source
// shared by transfer/bump-epoch/grant. Returns a nil Source (and an exit
// code) on any error, after printing it under prefix.
func setupOwnerSession(c *onchainConfig, stderr *os.File, prefix string) (ed25519.PrivateKey, ed25519.PublicKey, *walletsolana.Source, int) {
	owner, code := loadOwner(c.keypair, stderr)
	if owner == nil {
		return nil, nil, nil, code
	}
	sessionPub, err := c.sessionPub()
	if err != nil {
		fmt.Fprintln(stderr, prefix+":", err)
		return nil, nil, nil, 2
	}
	src, err := c.source(sessionPub)
	if err != nil {
		fmt.Fprintln(stderr, prefix+":", err)
		return nil, nil, nil, 2
	}
	return owner, sessionPub, src, 0
}

// parseOnchain parses fs, mapping -h to a clean exit. done is true when the
// caller should return code immediately.
func parseOnchain(fs *flag.FlagSet, args []string, stderr *os.File) (code int, done bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		fmt.Fprintln(stderr, fs.Name()+":", err)
		return 2, true
	}
	return 0, false
}

// loadOwner loads a Solana CLI keypair (JSON array of 64 bytes). Returns a
// nil key (and exit code) on error, after printing it.
func loadOwner(path string, stderr *os.File) (ed25519.PrivateKey, int) {
	if path == "" {
		fmt.Fprintln(stderr, "mosey session: --keypair is required (or set $SOLANA_KEYPAIR)")
		return nil, 2
	}
	key, err := loadSolanaKeypair(path)
	if err != nil {
		fmt.Fprintln(stderr, "mosey session: --keypair:", err)
		return nil, 2
	}
	return key, 0
}

// loadSolanaKeypair reads a Solana CLI keypair file: a JSON array of 64
// bytes (the ed25519 private key = seed || public key).
func loadSolanaKeypair(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b []byte
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("parse Solana keypair: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("Solana keypair has %d bytes, want %d", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

func printSig(stdout *os.File, rpc, sig string) {
	fmt.Fprintf(stdout, "  signature: %s\n", sig)
	if cluster := clusterParam(rpc); cluster != "" {
		fmt.Fprintf(stdout, "  explorer:  https://explorer.solana.com/tx/%s%s\n", sig, cluster)
	}
}

// clusterParam maps a known RPC endpoint to the explorer's ?cluster query.
func clusterParam(rpc string) string {
	switch {
	case rpc == "" || rpc == "https://api.mainnet-beta.solana.com":
		return ""
	case rpc == "https://api.devnet.solana.com":
		return "?cluster=devnet"
	case rpc == "https://api.testnet.solana.com":
		return "?cluster=testnet"
	default:
		return "?cluster=custom&customUrl=" + rpc
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
