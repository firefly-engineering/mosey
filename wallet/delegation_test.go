package wallet

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "regenerate testdata/delegation-vectors.json")

func keyFromSeed(b byte) ed25519.PrivateKey {
	seed := bytes.Repeat([]byte{b}, ed25519.SeedSize)
	return ed25519.NewKeyFromSeed(seed)
}

func pub(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

var (
	t0 = time.Date(2026, 6, 17, 14, 0, 0, 0, time.UTC)
	t1 = t0.Add(24 * time.Hour)
	at = t0.Add(time.Hour) // a "now" inside the window
)

func TestRenderParseRoundTrip(t *testing.T) {
	f := Fields{
		SessionID: pub(keyFromSeed(1)),
		Delegator: pub(keyFromSeed(2)),
		Delegate:  pub(keyFromSeed(3)),
		Caps:      CapWrite | CapResize,
		NotBefore: t0,
		NotAfter:  t1,
		Nonce:     bytes.Repeat([]byte{0xAB}, 16),
	}
	got, err := ParseContent(f.Render())
	if err != nil {
		t.Fatalf("ParseContent: %v", err)
	}
	if !got.SessionID.Equal(f.SessionID) || !got.Delegator.Equal(f.Delegator) ||
		!got.Delegate.Equal(f.Delegate) || got.Caps != f.Caps ||
		!got.NotBefore.Equal(f.NotBefore) || !got.NotAfter.Equal(f.NotAfter) ||
		!bytes.Equal(got.Nonce, f.Nonce) {
		t.Errorf("round-trip mismatch:\n in: %+v\nout: %+v", f, got)
	}
}

func TestParseContentRejectsOffGrammar(t *testing.T) {
	good := string(Fields{
		SessionID: pub(keyFromSeed(1)), Delegator: pub(keyFromSeed(2)),
		Delegate: pub(keyFromSeed(3)), Caps: CapWrite, NotBefore: t0, NotAfter: t1,
		Nonce: bytes.Repeat([]byte{1}, 16),
	}.Render())

	bad := []string{
		good + "\n", // trailing newline
		"wrong header" + good[len(contentHeader):], // bad header
		good[:len(good)-1],                         // truncated nonce char (bad base58 length)
	}
	for i, s := range bad {
		if _, err := ParseContent([]byte(s)); err == nil {
			t.Errorf("case %d: ParseContent accepted off-grammar input", i)
		}
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	priv := keyFromSeed(2)
	f := Fields{
		SessionID: pub(keyFromSeed(1)), Delegator: pub(priv), Delegate: pub(keyFromSeed(3)),
		Caps: CapWrite, NotBefore: t0, NotAfter: t1, Nonce: bytes.Repeat([]byte{1}, 16),
	}
	d := Sign(priv, f)
	if _, err := d.Verify(); err != nil {
		t.Fatalf("Verify of a good delegation: %v", err)
	}

	tamperedContent := append([]byte(nil), d.Content...)
	tamperedContent[len(tamperedContent)-1] ^= 0xFF
	if _, err := (Delegation{Content: tamperedContent, Signature: d.Signature}).Verify(); err == nil {
		t.Error("Verify accepted tampered content")
	}

	tamperedSig := append([]byte(nil), d.Signature...)
	tamperedSig[0] ^= 0xFF
	if _, err := (Delegation{Content: d.Content, Signature: tamperedSig}).Verify(); err == nil {
		t.Error("Verify accepted tampered signature")
	}
}

// delegate signs f with priv (which must match f.Delegator).
func mkDeleg(priv ed25519.PrivateKey, session, delegate ed25519.PublicKey, caps Caps) Delegation {
	return Sign(priv, Fields{
		SessionID: session, Delegator: pub(priv), Delegate: delegate,
		Caps: caps, NotBefore: t0, NotAfter: t1, Nonce: bytes.Repeat([]byte{7}, 16),
	})
}

func TestFold(t *testing.T) {
	session := pub(keyFromSeed(99))
	ownerPriv := keyFromSeed(1)
	owner := pub(ownerPriv)
	viewerPriv := keyFromSeed(2)
	viewer := pub(viewerPriv)
	kc := pub(keyFromSeed(50)) // the connection key
	snap := NewMemSnapshot(owner).
		WithGrant(viewer, CapWrite). // on-chain grant: write, no forge
		WithGrant(pub(keyFromSeed(3)), CapWrite|CapForge)

	t.Run("owner direct to Kc", func(t *testing.T) {
		chain := []Delegation{mkDeleg(ownerPriv, session, kc, AllCaps)}
		caps, isOwner, err := Fold(chain, kc, session, snap, at)
		if err != nil || !isOwner || caps != AllCaps {
			t.Fatalf("got (%v, %v, %v)", caps, isOwner, err)
		}
	})

	t.Run("on-chain grantee self-delegation", func(t *testing.T) {
		// viewer has an on-chain write grant (no forge) and self-delegates
		// view-only-narrowing to its own Kc — a single leaf hop, allowed.
		chain := []Delegation{mkDeleg(viewerPriv, session, kc, CapWrite)}
		caps, isOwner, err := Fold(chain, kc, session, snap, at)
		if err != nil || isOwner || caps != CapWrite {
			t.Fatalf("got (%v, %v, %v)", caps, isOwner, err)
		}
	})

	t.Run("off-chain two hop from owner", func(t *testing.T) {
		// owner (forge) -> viewer wallet -> Kc
		chain := []Delegation{
			mkDeleg(ownerPriv, session, viewer, CapWrite),
			mkDeleg(viewerPriv, session, kc, CapWrite),
		}
		caps, isOwner, err := Fold(chain, kc, session, snap, at)
		if err != nil || !isOwner || caps != CapWrite {
			t.Fatalf("got (%v, %v, %v)", caps, isOwner, err)
		}
	})

	t.Run("viewer cannot forge to a third party", func(t *testing.T) {
		third := pub(keyFromSeed(4))
		// owner -> viewer(write, no forge) -> third -> Kc : the viewer hop
		// is non-leaf, so the viewer needs FORGE, which it lacks.
		chain := []Delegation{
			mkDeleg(ownerPriv, session, viewer, CapWrite),
			mkDeleg(viewerPriv, session, third, CapWrite),
			mkDeleg(keyFromSeed(4), session, kc, CapWrite),
		}
		if _, _, err := Fold(chain, kc, session, snap, at); err != ErrForgeRequired {
			t.Fatalf("want ErrForgeRequired, got %v", err)
		}
	})

	t.Run("rejections", func(t *testing.T) {
		cases := []struct {
			name  string
			chain []Delegation
			leaf  ed25519.PublicKey
			now   time.Time
			want  error
		}{
			{"empty", nil, kc, at, ErrEmptyChain},
			{"widening", []Delegation{mkDeleg(viewerPriv, session, kc, AllCaps)}, kc, at, ErrAttenuation},
			{"unknown root", []Delegation{mkDeleg(keyFromSeed(77), session, kc, CapWrite)}, kc, at, ErrUnknownRoot},
			{"wrong leaf", []Delegation{mkDeleg(ownerPriv, session, kc, AllCaps)}, pub(keyFromSeed(51)), at, ErrLeafMismatch},
			{"expired", []Delegation{mkDeleg(ownerPriv, session, kc, AllCaps)}, kc, t1.Add(time.Hour), ErrExpired},
			{"wrong session", []Delegation{mkDeleg(ownerPriv, pub(keyFromSeed(98)), kc, AllCaps)}, kc, at, ErrWrongSession},
			{"broken link", []Delegation{
				mkDeleg(ownerPriv, session, viewer, AllCaps),
				mkDeleg(keyFromSeed(4), session, kc, CapWrite), // delegator != viewer
			}, kc, at, ErrBrokenLink},
		}
		for _, tc := range cases {
			if _, _, err := Fold(tc.chain, tc.leaf, session, snap, tc.now); err != tc.want {
				t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
			}
		}
	})
}

// --- cross-language golden vectors -------------------------------------

type goldenVector struct {
	Name          string `json:"name"`
	Session       string `json:"session"`
	Delegator     string `json:"delegator"`
	Delegate      string `json:"delegate"`
	Caps          string `json:"caps"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	NonceHex      string `json:"nonce_hex"`
	SignerSeedHex string `json:"signer_seed_hex"`
	Content       string `json:"content"`
	SignatureB58  string `json:"signature_base58"`
}

type goldenFile struct {
	Comment string         `json:"_comment"`
	Vectors []goldenVector `json:"vectors"`
}

var goldenPath = filepath.Join("testdata", "delegation-vectors.json")

func goldenFixtures() []goldenVector {
	type fx struct {
		name                    string
		signer, session, delPub byte
		caps                    Caps
		nonce                   byte
	}
	out := []goldenVector{}
	for _, x := range []fx{
		{"owner-all-caps", 2, 1, 3, AllCaps, 0x11},
		{"view-only", 4, 1, 5, 0, 0xA0},
		{"write-only", 6, 1, 7, CapWrite, 0x5C},
	} {
		signerPriv := keyFromSeed(x.signer)
		nonce := bytes.Repeat([]byte{x.nonce}, 16)
		f := Fields{
			SessionID: pub(keyFromSeed(x.session)),
			Delegator: pub(signerPriv),
			Delegate:  pub(keyFromSeed(x.delPub)),
			Caps:      x.caps,
			NotBefore: t0,
			NotAfter:  t1,
			Nonce:     nonce,
		}
		d := Sign(signerPriv, f)
		out = append(out, goldenVector{
			Name:          x.name,
			Session:       base58Encode(f.SessionID),
			Delegator:     base58Encode(f.Delegator),
			Delegate:      base58Encode(f.Delegate),
			Caps:          f.Caps.String(),
			NotBefore:     renderTime(f.NotBefore),
			NotAfter:      renderTime(f.NotAfter),
			NonceHex:      hex.EncodeToString(nonce),
			SignerSeedHex: hex.EncodeToString(bytes.Repeat([]byte{x.signer}, ed25519.SeedSize)),
			Content:       string(d.Content),
			SignatureB58:  base58Encode(d.Signature),
		})
	}
	return out
}

func TestGoldenVectors(t *testing.T) {
	if *update {
		blob, err := json.MarshalIndent(goldenFile{
			Comment: "Cross-language fixtures for the canonical delegation text. " +
				"Go (wallet) and TS (clients/typescript) must both render byte-identical " +
				"content and verify the signature. Regenerate with: go test ./wallet -run Golden -update",
			Vectors: goldenFixtures(),
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, append(blob, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", goldenPath)
		return
	}

	blob, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to generate): %v", err)
	}
	var gf goldenFile
	if err := json.Unmarshal(blob, &gf); err != nil {
		t.Fatal(err)
	}
	if len(gf.Vectors) == 0 {
		t.Fatal("no golden vectors")
	}
	for _, v := range gf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			f := fieldsFromVector(t, v)
			if got := string(f.Render()); got != v.Content {
				t.Errorf("render mismatch:\n got: %q\nwant: %q", got, v.Content)
			}
			sig, err := base58Decode(v.SignatureB58)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := (Delegation{Content: []byte(v.Content), Signature: sig}).Verify(); err != nil {
				t.Errorf("verify committed signature: %v", err)
			}
			// Determinism: re-signing the seed must reproduce the signature.
			seed, _ := hex.DecodeString(v.SignerSeedHex)
			d := Sign(ed25519.NewKeyFromSeed(seed), f)
			if base58Encode(d.Signature) != v.SignatureB58 {
				t.Error("re-signed signature does not match committed vector")
			}
		})
	}
}

func fieldsFromVector(t *testing.T, v goldenVector) Fields {
	t.Helper()
	dec := func(s string) ed25519.PublicKey {
		b, err := base58Decode(s)
		if err != nil {
			t.Fatalf("base58 %q: %v", s, err)
		}
		return ed25519.PublicKey(b)
	}
	caps, err := ParseCaps(v.Caps)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := parseTime(v.NotBefore)
	if err != nil {
		t.Fatal(err)
	}
	na, err := parseTime(v.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(v.NonceHex)
	if err != nil {
		t.Fatal(err)
	}
	return Fields{
		SessionID: dec(v.Session), Delegator: dec(v.Delegator), Delegate: dec(v.Delegate),
		Caps: caps, NotBefore: nb, NotAfter: na, Nonce: nonce,
	}
}
