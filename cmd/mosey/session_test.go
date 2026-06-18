package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/firefly-engineering/mosey/wallet"
)

// writeSolanaKeypair writes a key in the Solana CLI format (JSON array of
// the 64 private-key bytes).
func writeSolanaKeypair(t *testing.T, dir string, priv ed25519.PrivateKey) string {
	t.Helper()
	ints := make([]int, len(priv))
	for i, b := range priv {
		ints[i] = int(b)
	}
	blob, err := json.Marshal(ints)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "owner.json")
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSolanaKeypairRoundTrip(t *testing.T) {
	dir := t.TempDir()
	_, priv := genKey(t)
	path := writeSolanaKeypair(t, dir, priv)

	got, err := loadSolanaKeypair(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(priv) {
		t.Error("loaded Solana keypair does not match written key")
	}
}

func TestLoadSolanaKeypairRejectsWrongLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short.json")
	if err := os.WriteFile(path, []byte("[1,2,3]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSolanaKeypair(path); err == nil {
		t.Error("expected error for a 3-byte keypair")
	}
}

func TestSessionPubResolution(t *testing.T) {
	dir := t.TempDir()
	pub, priv := genKey(t)

	// Via --wallet-session-key (a hex private key file).
	hexPath := filepath.Join(dir, "session.hex")
	if err := os.WriteFile(hexPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	c := onchainConfig{sessionKey: hexPath}
	got, err := c.sessionPub()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Error("--wallet-session-key resolved to the wrong public key")
	}

	// Via --session (a base58 public key).
	c2 := onchainConfig{session: wallet.Address(pub)}
	got2, err := c2.sessionPub()
	if err != nil {
		t.Fatal(err)
	}
	if !got2.Equal(pub) {
		t.Error("--session resolved to the wrong public key")
	}

	// Neither set → error.
	if _, err := (&onchainConfig{}).sessionPub(); err == nil {
		t.Error("expected error when neither --session nor --wallet-session-key is set")
	}
}

func TestClusterParam(t *testing.T) {
	cases := map[string]string{
		"https://api.devnet.solana.com":       "?cluster=devnet",
		"https://api.testnet.solana.com":      "?cluster=testnet",
		"https://api.mainnet-beta.solana.com": "",
		"":                                    "",
	}
	for rpc, want := range cases {
		if got := clusterParam(rpc); got != want {
			t.Errorf("clusterParam(%q) = %q, want %q", rpc, got, want)
		}
	}
	if got := clusterParam("http://localhost:8899"); got == "" {
		t.Error("custom RPC should produce a customUrl cluster param")
	}
}

func TestRunSessionValidation(t *testing.T) {
	null := devNull(t)
	// No subcommand.
	if runSession(nil, null, null) != 2 {
		t.Error("no subcommand should exit 2")
	}
	// Unknown subcommand.
	if runSession([]string{"frobnicate"}, null, null) != 2 {
		t.Error("unknown subcommand should exit 2")
	}
	// register without the session key.
	if runSessionRegister([]string{"--program=x", "--keypair=y"}, null, null) != 2 {
		t.Error("register without --wallet-session-key should exit 2")
	}
	// grant without --to.
	if runSessionGrant([]string{"--session=" + wallet.Address(mustPubKey(t))}, null, null) != 2 {
		t.Error("grant without --to should exit 2")
	}
}

func mustPubKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _ := genKey(t)
	return pub
}
