package cert_test

import (
	"strings"
	"testing"

	"github.com/firefly-engineering/ship/internal/cert"
)

func TestNewMasterMnemonic_24Words(t *testing.T) {
	t.Parallel()
	mnemonic, priv, err := cert.NewMasterMnemonic()
	if err != nil {
		t.Fatalf("NewMasterMnemonic: %v", err)
	}
	words := strings.Fields(mnemonic)
	if len(words) != 24 {
		t.Errorf("got %d words, want 24", len(words))
	}
	if len(priv) == 0 {
		t.Error("priv is empty")
	}
	if pub := cert.MasterPublicKey(priv); len(pub) == 0 {
		t.Error("derived public key is empty")
	}
}

func TestMasterFromMnemonic_RoundTrip(t *testing.T) {
	t.Parallel()
	mnemonic, want, err := cert.NewMasterMnemonic()
	if err != nil {
		t.Fatalf("NewMasterMnemonic: %v", err)
	}
	got, err := cert.MasterFromMnemonic(mnemonic)
	if err != nil {
		t.Fatalf("MasterFromMnemonic: %v", err)
	}
	if !equalKeys(got, want) {
		t.Error("re-derivation produced a different key")
	}
}

func TestMasterFromMnemonic_RejectsInvalid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		mnemonic string
	}{
		{"empty", ""},
		{"single word", "wallet"},
		{"checksum failure", "wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := cert.MasterFromMnemonic(tc.mnemonic); err == nil {
				t.Errorf("expected error for %q, got nil", tc.mnemonic)
			}
		})
	}
}

func TestMasterFromMnemonic_DifferentMnemonicsDifferKeys(t *testing.T) {
	t.Parallel()
	m1, _, err := cert.NewMasterMnemonic()
	if err != nil {
		t.Fatalf("m1: %v", err)
	}
	m2, _, err := cert.NewMasterMnemonic()
	if err != nil {
		t.Fatalf("m2: %v", err)
	}
	if m1 == m2 {
		t.Skip("two random mnemonics collided — astronomically unlikely; rerun")
	}
	k1, _ := cert.MasterFromMnemonic(m1)
	k2, _ := cert.MasterFromMnemonic(m2)
	if equalKeys(k1, k2) {
		t.Error("different mnemonics produced same key")
	}
}

func equalKeys(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
