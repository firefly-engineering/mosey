package walletsolana

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestAppendShortVec(t *testing.T) {
	// Compact-u16 (shortvec) golden encodings.
	cases := []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x01}},
		{255, []byte{0xff, 0x01}},
		{16383, []byte{0xff, 0x7f}},
		{16384, []byte{0x80, 0x80, 0x01}},
	}
	for _, c := range cases {
		if got := appendShortVec(nil, c.n); !bytes.Equal(got, c.want) {
			t.Errorf("appendShortVec(%d) = %x, want %x", c.n, got, c.want)
		}
	}
}

func TestIxDiscriminator(t *testing.T) {
	// 8 bytes, deterministic, and distinct per instruction name.
	a := ixDiscriminator("register_session")
	b := ixDiscriminator("register_session")
	c := ixDiscriminator("grant")
	if a != b {
		t.Error("discriminator not deterministic")
	}
	if a == c {
		t.Error("distinct instructions share a discriminator")
	}
	if len(a) != 8 {
		t.Errorf("discriminator length %d, want 8", len(a))
	}
}

func TestFindPDADeterministicAndOffCurve(t *testing.T) {
	var prog pubkey
	for i := range prog {
		prog[i] = byte(i + 1)
	}
	seed := []byte("session")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xA0 + i)
	}

	addr1, bump1, err := findPDA(prog, seed, key)
	if err != nil {
		t.Fatal(err)
	}
	addr2, bump2, err := findPDA(prog, seed, key)
	if err != nil {
		t.Fatal(err)
	}
	if addr1 != addr2 || bump1 != bump2 {
		t.Error("findPDA not deterministic")
	}
	if onCurve(addr1) {
		t.Error("PDA must not be a valid curve point")
	}
}

func TestOnCurveAcceptsRealPubkey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !onCurve(toPubkey(pub)) {
		t.Error("a real ed25519 public key should be on the curve")
	}
}

func TestCompileMessageRegisterOrdering(t *testing.T) {
	// Mirror register_session's account list: PDA (writable, non-signer),
	// session key (signer, ro), owner (signer, writable = fee payer),
	// system program (ro, non-signer).
	var prog, sessionAddr, sysProg pubkey
	prog[0], sessionAddr[0], sysProg[0] = 1, 2, 0 // sysProg = all-zero
	owner := mustPub(t, 0x10)
	sessKey := mustPub(t, 0x20)

	ix := instruction{
		programID: prog,
		accounts: []accountMeta{
			{key: sessionAddr, isSigner: false, writable: true},
			{key: toPubkey(sessKey), isSigner: true, writable: false},
			{key: toPubkey(owner), isSigner: true, writable: true},
			{key: sysProg, isSigner: false, writable: false},
		},
		data: []byte{1, 2, 3},
	}
	var bh [32]byte
	msg, err := compileMessage(toPubkey(owner), bh, []instruction{ix})
	if err != nil {
		t.Fatal(err)
	}

	// Fee payer (owner) must be first; it is the only writable signer.
	if msg.accountKeys[0] != toPubkey(owner) {
		t.Error("fee payer must be account 0")
	}
	// Two signers: owner (writable) then session key (readonly).
	if msg.numSigners != 2 {
		t.Errorf("numSigners = %d, want 2", msg.numSigners)
	}
	if msg.accountKeys[1] != toPubkey(sessKey) {
		t.Error("readonly signer (session key) should be account 1")
	}
	// Header: [numRequiredSignatures, numReadonlySigned, numReadonlyUnsigned].
	if msg.serialized[0] != 2 || msg.serialized[1] != 1 {
		t.Errorf("header = %v, want numSigners=2 readonlySigned=1", msg.serialized[:3])
	}
	// readonly-unsigned = system program + program id = 2.
	if msg.serialized[2] != 2 {
		t.Errorf("readonlyUnsigned = %d, want 2", msg.serialized[2])
	}
}

func mustPub(t *testing.T, fill byte) ed25519.PublicKey {
	t.Helper()
	b := make([]byte, ed25519.PublicKeySize)
	for i := range b {
		b[i] = fill + byte(i)
	}
	return ed25519.PublicKey(b)
}
