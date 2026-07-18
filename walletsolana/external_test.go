package walletsolana_test

// Black-box tests (package walletsolana_test) proving the two seams this
// package exposes to outside callers: keyless construction for the
// write/dashboard paths, and the exported Options.Call injection point,
// which lets an external package drive the account-layout wiring
// (getProgramAccounts filter, PDA-based address derivation) without a live
// node.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/firefly-engineering/mosey/walletsolana"
)

// newKey returns a deterministic ed25519 public key for tests.
func newKey(t *testing.T, seed byte) ed25519.PublicKey {
	t.Helper()
	b := make([]byte, ed25519.SeedSize)
	b[0] = seed
	return ed25519.NewKeyFromSeed(b).Public().(ed25519.PublicKey)
}

// TestKeylessConstruction verifies a Source built without a SessionKey is
// usable for the write/dashboard paths, and that the read path reports the
// missing session instead of panicking or reading a zero key.
func TestKeylessConstruction(t *testing.T) {
	src, err := walletsolana.New(walletsolana.Options{
		RPCEndpoint: "https://example.invalid",
		ProgramID:   "6Scr7CxNU5tHy4vBqjBQXWTC5uMhZzT6nHXFqhQ7Wnjc",
	})
	if err != nil {
		t.Fatalf("New without SessionKey: %v", err)
	}

	// Read path is unavailable without a session; it must say so rather
	// than serve a snapshot for the zero key.
	if _, _, err := src.Snapshot(); err == nil {
		t.Fatal("Snapshot on keyless Source: want error, got nil")
	}
	if err := src.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh on keyless Source: want error, got nil")
	}
}

// TestMalformedSessionKeyStillFailsFast verifies a present-but-wrong-length
// key is rejected at construction (only the absent case is deferred).
func TestMalformedSessionKeyStillFailsFast(t *testing.T) {
	_, err := walletsolana.New(walletsolana.Options{
		RPCEndpoint: "https://example.invalid",
		ProgramID:   "6Scr7CxNU5tHy4vBqjBQXWTC5uMhZzT6nHXFqhQ7Wnjc",
		SessionKey:  make(ed25519.PublicKey, 20), // not 32 bytes
	})
	if err == nil {
		t.Fatal("New with 20-byte SessionKey: want error, got nil")
	}
}

// TestExportedCallSeam drives SessionsByOwner through the exported Call
// injection point — no live node — proving an external package can now
// exercise the account-layout wiring the read path also depends on.
func TestExportedCallSeam(t *testing.T) {
	owner := newKey(t, 1)
	var gotMethod string
	var gotParams []any

	src, err := walletsolana.New(walletsolana.Options{
		ProgramID: "6Scr7CxNU5tHy4vBqjBQXWTC5uMhZzT6nHXFqhQ7Wnjc",
		Call: func(_ context.Context, method string, params []any) (json.RawMessage, error) {
			gotMethod, gotParams = method, params
			return json.RawMessage(`[]`), nil // no accounts
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sessions, err := src.SessionsByOwner(context.Background(), owner)
	if err != nil {
		t.Fatalf("SessionsByOwner: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("SessionsByOwner: want 0 sessions, got %d", len(sessions))
	}
	if gotMethod != "getProgramAccounts" {
		t.Fatalf("Call method: want getProgramAccounts, got %q", gotMethod)
	}
	if len(gotParams) == 0 {
		t.Fatal("Call params: want the program id + filter, got none")
	}
}

// TestExportedCallSeamError confirms an error from the injected Call
// propagates out of the account-layout path.
func TestExportedCallSeamError(t *testing.T) {
	sentinel := errors.New("rpc down")
	src, err := walletsolana.New(walletsolana.Options{
		ProgramID: "6Scr7CxNU5tHy4vBqjBQXWTC5uMhZzT6nHXFqhQ7Wnjc",
		Call: func(context.Context, string, []any) (json.RawMessage, error) {
			return nil, sentinel
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := src.SessionsByOwner(context.Background(), newKey(t, 2)); !errors.Is(err, sentinel) {
		t.Fatalf("SessionsByOwner error: want %v, got %v", sentinel, err)
	}
}
