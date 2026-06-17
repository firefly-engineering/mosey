// Spike: independently re-render the canonical delegation text in Go from
// the fields sign.mjs chose, assert it is byte-identical to what JS
// produced, then verify the Ed25519 signature over those bytes.
//
//	node sign.mjs | go run verify.go
//	node sign.mjs view-only | go run verify.go
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
)

type input struct {
	Fields struct {
		Session   string `json:"session"`
		Delegator string `json:"delegator"`
		Delegate  string `json:"delegate"`
		Caps      string `json:"caps"`
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
		Nonce     string `json:"nonce"`
	} `json:"fields"`
	ContentHex   string `json:"content_hex"`
	PubkeyBase58 string `json:"pubkey_base58"`
	SigBase58    string `json:"sig_base58"`
}

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func b58decode(s string) ([]byte, error) {
	n := big.NewInt(0)
	radix := big.NewInt(58)
	for _, c := range s {
		idx := strings.IndexRune(b58Alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 char %q", c)
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(idx)))
	}
	out := n.Bytes()
	for i := 0; i < len(s) && s[i] == '1'; i++ { // leading '1' => leading zero byte
		out = append([]byte{0}, out...)
	}
	return out, nil
}

// Independent Go renderer — must match sign.mjs byte for byte.
func render(f input) string {
	return strings.Join([]string{
		"mosey session authorization v1",
		"",
		"session: " + f.Fields.Session,
		"delegator: " + f.Fields.Delegator,
		"delegate: " + f.Fields.Delegate,
		"caps: " + f.Fields.Caps,
		"not-before: " + f.Fields.NotBefore,
		"not-after: " + f.Fields.NotAfter,
		"nonce: " + f.Fields.Nonce,
	}, "\n")
}

func main() {
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Println("FAIL: decode stdin:", err)
		os.Exit(1)
	}

	goContent := render(in)
	goHex := hex.EncodeToString([]byte(goContent))

	fail := false
	if goHex == in.ContentHex {
		fmt.Println("PASS  byte-identical render (Go == JS),", len(goContent), "bytes")
	} else {
		fail = true
		fmt.Println("FAIL  render mismatch")
		fmt.Println("  JS:", in.ContentHex)
		fmt.Println("  Go:", goHex)
	}

	pub, err := b58decode(in.PubkeyBase58)
	if err != nil || len(pub) != 32 {
		fail = true
		fmt.Printf("FAIL  pubkey decode: %v (len %d)\n", err, len(pub))
	}
	sig, err := b58decode(in.SigBase58)
	if err != nil || len(sig) != 64 {
		fail = true
		fmt.Printf("FAIL  sig decode: %v (len %d)\n", err, len(sig))
	}

	if !fail {
		if ed25519.Verify(ed25519.PublicKey(pub), []byte(goContent), sig) {
			fmt.Println("PASS  Ed25519 signature verifies in Go over the raw UTF-8 content")
		} else {
			fail = true
			fmt.Println("FAIL  signature does NOT verify over raw bytes")
		}
	}

	fmt.Println("\n--- the bytes a wallet would display & sign ---")
	fmt.Println(goContent)
	fmt.Println("-----------------------------------------------")

	if fail {
		os.Exit(1)
	}
}
