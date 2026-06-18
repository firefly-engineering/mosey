package wallet

import (
	"bytes"
	"testing"
)

func TestChainRoundTrip(t *testing.T) {
	priv := keyFromSeed(1)
	chain := []Delegation{
		Sign(priv, Fields{
			SessionID: pub(keyFromSeed(9)), Delegator: pub(priv), Delegate: pub(keyFromSeed(3)),
			Caps: CapWrite | CapForge, NotBefore: t0, NotAfter: t1, Nonce: bytes.Repeat([]byte{2}, 16),
		}),
		Sign(keyFromSeed(3), Fields{
			SessionID: pub(keyFromSeed(9)), Delegator: pub(keyFromSeed(3)), Delegate: pub(keyFromSeed(4)),
			Caps: CapWrite, NotBefore: t0, NotAfter: t1, Nonce: bytes.Repeat([]byte{5}, 16),
		}),
	}

	blob, err := EncodeChain(chain)
	if err != nil {
		t.Fatalf("EncodeChain: %v", err)
	}
	got, err := DecodeChain(blob)
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	if len(got) != len(chain) {
		t.Fatalf("got %d delegations, want %d", len(got), len(chain))
	}
	for i := range chain {
		if !bytes.Equal(got[i].Content, chain[i].Content) || !bytes.Equal(got[i].Signature, chain[i].Signature) {
			t.Errorf("delegation %d did not round-trip", i)
		}
	}
}

func TestDecodeChainRejectsGarbage(t *testing.T) {
	if _, err := DecodeChain([]byte("not json")); err == nil {
		t.Error("DecodeChain accepted non-JSON")
	}
}
