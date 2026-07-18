package walletsolana

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/firefly-engineering/mosey/wallet"
)

// TestCompileUnsignedTx proves the unsigned transaction is exactly the
// signed transaction with the fee-payer signature zeroed: a browser
// wallet that fills the signature slot produces a valid signed tx. This
// is the contract `mosey web`'s on-chain governance relies on.
func TestCompileUnsignedTx(t *testing.T) {
	ownerPubKey, ownerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sessionPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newOwnerPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	progPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	src, err := New(Options{
		ProgramID:  wallet.EncodeBase58(progPubKey),
		SessionKey: sessionPubKey,
		Call: func(context.Context, string, []any) (json.RawMessage, error) {
			return nil, nil // ix building needs no RPC
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	op := toPubkey(ownerPubKey)
	ix, err := src.transferOwnershipIx(op, sessionPubKey, newOwnerPubKey)
	if err != nil {
		t.Fatalf("transferOwnershipIx: %v", err)
	}
	var bh [32]byte
	for i := range bh {
		bh[i] = byte(i + 1)
	}
	msg, err := compileMessage(op, bh, []instruction{ix})
	if err != nil {
		t.Fatalf("compileMessage: %v", err)
	}
	if msg.numSigners != 1 {
		t.Fatalf("numSigners = %d, want 1 (owner only)", msg.numSigners)
	}

	signed, err := signTx(msg, map[pubkey]ed25519.PrivateKey{op: ownerKey})
	if err != nil {
		t.Fatalf("signTx: %v", err)
	}
	unsigned := compileUnsignedTx(msg)

	// Same length and layout: 1-byte sig count, one 64-byte sig slot, message.
	if len(unsigned) != len(signed) {
		t.Fatalf("unsigned len %d != signed len %d", len(unsigned), len(signed))
	}
	if unsigned[0] != 1 || signed[0] != 1 {
		t.Fatalf("sig count byte: unsigned=%d signed=%d, want 1", unsigned[0], signed[0])
	}
	for i := 1; i < 1+64; i++ {
		if unsigned[i] != 0 {
			t.Fatalf("unsigned sig slot byte %d = %d, want 0", i, unsigned[i])
		}
	}
	// Message bodies (everything after the sig slot) must match.
	if !bytes.Equal(unsigned[1+64:], signed[1+64:]) {
		t.Fatal("message body differs between unsigned and signed tx")
	}
	// Filling the unsigned sig slot with the owner's signature over the
	// message yields exactly the signed tx.
	filled := append([]byte(nil), unsigned...)
	copy(filled[1:1+64], ed25519.Sign(ownerKey, msg.serialized))
	if !bytes.Equal(filled, signed) {
		t.Fatal("unsigned tx + owner signature != signed tx")
	}
}
