// runGrant implements `mosey grant` — sign an off-chain delegation that
// authorizes someone to attach to a wallet-auth session. The signer
// (owner, or a forge-capable delegate) holds an Ed25519 key; the grant
// is a one-hop delegation rooted at that signer.
//
// Two channels:
//   - bearer (default): a fresh connection key K_c is generated and the
//     grant delegates to it; the recipient gets both the chain and the
//     key and needs no wallet of their own.
//   - wallet-bound (--to ADDRESS): the grant delegates to a known
//     wallet, which then self-delegates to its own K_c at attach time.
package main

import (
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

	"github.com/firefly-engineering/mosey/wallet"
)

func runGrant(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("mosey grant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keypair := fs.String("wallet-keypair", "", "path to the signer's Ed25519 key (the owner, or a delegate holding the forge cap)")
	session := fs.String("session", "", "base58 session address this grant is scoped to")
	capsStr := fs.String("caps", "view-only", "caps to grant: comma-separated write,resize,forge — or view-only")
	expires := fs.Duration("expires", 24*time.Hour, "validity duration from now")
	to := fs.String("to", "", "base58 delegate address (wallet-bound grant); omit for a bearer grant")
	out := fs.String("out", ".", "output directory for grant.json (and conn.key for bearer grants)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "mosey grant:", err)
		return 2
	}
	if *keypair == "" || *session == "" {
		fmt.Fprintln(stderr, "mosey grant: --wallet-keypair and --session are required")
		return 2
	}

	signerPriv, err := loadHexKey(*keypair)
	if err != nil {
		fmt.Fprintln(stderr, "mosey grant: --wallet-keypair:", err)
		return 2
	}
	sessionID, err := wallet.ParseAddress(*session)
	if err != nil {
		fmt.Fprintln(stderr, "mosey grant: --session:", err)
		return 2
	}
	caps, err := wallet.ParseCaps(*capsStr)
	if err != nil {
		fmt.Fprintln(stderr, "mosey grant: --caps:", err)
		return 2
	}

	// Resolve the delegate: a named wallet, or a fresh bearer key.
	var (
		delegate ed25519.PublicKey
		bearer   ed25519.PrivateKey
	)
	if *to != "" {
		if delegate, err = wallet.ParseAddress(*to); err != nil {
			fmt.Fprintln(stderr, "mosey grant: --to:", err)
			return 2
		}
	} else {
		if _, bearer, err = ed25519.GenerateKey(rand.Reader); err != nil {
			fmt.Fprintln(stderr, "mosey grant: generate bearer key:", err)
			return 1
		}
		delegate = bearer.Public().(ed25519.PublicKey)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		fmt.Fprintln(stderr, "mosey grant: nonce:", err)
		return 1
	}
	now := time.Now()
	deleg := wallet.Sign(signerPriv, wallet.Fields{
		SessionID: sessionID,
		Delegator: signerPriv.Public().(ed25519.PublicKey),
		Delegate:  delegate,
		Caps:      caps,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(*expires),
		Nonce:     nonce,
	})
	blob, err := wallet.EncodeChain([]wallet.Delegation{deleg})
	if err != nil {
		fmt.Fprintln(stderr, "mosey grant: encode chain:", err)
		return 1
	}

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(stderr, "mosey grant: --out:", err)
		return 1
	}
	grantPath := filepath.Join(*out, "grant.json")
	if err := os.WriteFile(grantPath, blob, 0o644); err != nil {
		fmt.Fprintln(stderr, "mosey grant: write grant:", err)
		return 1
	}

	fmt.Fprintf(stdout, "mosey grant: wrote %s (caps: %s, expires %s)\n", grantPath, caps, now.Add(*expires).UTC().Format(time.RFC3339))
	if bearer != nil {
		connPath := filepath.Join(*out, "conn.key")
		if err := os.WriteFile(connPath, []byte(hex.EncodeToString(bearer)+"\n"), 0o600); err != nil {
			fmt.Fprintln(stderr, "mosey grant: write conn key:", err)
			return 1
		}
		fmt.Fprintf(stdout, "mosey grant: wrote %s (bearer connection key)\n", connPath)
		fmt.Fprintf(stdout, "\nThe recipient attaches with:\n  mosey attach --wallet-grant=%s --wallet-conn-key=%s --wallet-session=%s ENDPOINT\n",
			grantPath, connPath, *session)
	} else {
		fmt.Fprintf(stdout, "\nGranted to %s. They self-delegate to their own connection key at attach time.\n", *to)
	}
	return 0
}

func loadHexKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(dec) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("decoded length %d, want %d", len(dec), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(dec), nil
}
