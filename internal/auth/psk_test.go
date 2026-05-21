package auth_test

import (
	"strings"
	"testing"

	"github.com/firefly-engineering/ship/internal/auth"
)

func TestNewPSKAuth_RejectsEmptySecret(t *testing.T) {
	t.Parallel()
	if _, err := auth.NewPSKAuth(""); err == nil {
		t.Fatal("empty secret must error")
	}
}

func TestPSKAuth_NameIsStable(t *testing.T) {
	t.Parallel()
	a, err := auth.NewPSKAuth("hunter2")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}
	if got := a.Name(); got != "psk" {
		t.Errorf("Name = %q, want psk", got)
	}
}

func TestPSKAuth_HostOptionsReturned(t *testing.T) {
	t.Parallel()
	a, err := auth.NewPSKAuth("hunter2")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}
	opts := a.HostOptions()
	if len(opts) == 0 {
		t.Fatal("HostOptions returned empty slice; need at least the pnet protector")
	}
}

func TestPSKAuth_VerifyPeerIsNoop(t *testing.T) {
	t.Parallel()
	a, err := auth.NewPSKAuth("hunter2")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}
	// PSK gates at the transport layer; VerifyPeer just returns nil.
	if err := a.VerifyPeer("", nil); err != nil {
		t.Errorf("VerifyPeer = %v, want nil", err)
	}
}

func TestPSKAuth_SameSecretSameKey(t *testing.T) {
	t.Parallel()
	a1, err := auth.NewPSKAuth("hunter2")
	if err != nil {
		t.Fatalf("NewPSKAuth 1: %v", err)
	}
	a2, err := auth.NewPSKAuth("hunter2")
	if err != nil {
		t.Fatalf("NewPSKAuth 2: %v", err)
	}
	if a1.KeyHex() != a2.KeyHex() {
		t.Errorf("identical secrets produced different keys:\n  %s\n  %s", a1.KeyHex(), a2.KeyHex())
	}
}

func TestPSKAuth_DifferentSecretsDifferentKeys(t *testing.T) {
	t.Parallel()
	a1, err := auth.NewPSKAuth("hunter2")
	if err != nil {
		t.Fatalf("NewPSKAuth 1: %v", err)
	}
	a2, err := auth.NewPSKAuth("hunter3")
	if err != nil {
		t.Fatalf("NewPSKAuth 2: %v", err)
	}
	if a1.KeyHex() == a2.KeyHex() {
		t.Errorf("different secrets produced same key: %s", a1.KeyHex())
	}
}

func TestPSKAuth_KeyHexIsHex(t *testing.T) {
	t.Parallel()
	a, err := auth.NewPSKAuth("hunter2")
	if err != nil {
		t.Fatalf("NewPSKAuth: %v", err)
	}
	hex := a.KeyHex()
	if len(hex) != 64 {
		t.Errorf("KeyHex length = %d, want 64 (32 bytes hex-encoded)", len(hex))
	}
	if strings.IndexFunc(hex, func(r rune) bool {
		return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'))
	}) >= 0 {
		t.Errorf("KeyHex contains non-hex chars: %s", hex)
	}
}
