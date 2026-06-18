package wallet

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"strings"
)

// base58Alphabet is the Bitcoin / Solana alphabet.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Address renders a public key as its base58 (Solana) address string —
// the human-facing identity used in delegations and labels.
func Address(pub ed25519.PublicKey) string { return base58Encode(pub) }

// ParseAddress decodes a base58 (Solana) address into an Ed25519 public
// key, rejecting anything that is not exactly 32 bytes.
func ParseAddress(s string) (ed25519.PublicKey, error) {
	b, err := base58Decode(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("wallet: address is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// base58Encode encodes b using the Bitcoin/Solana alphabet, mapping each
// leading zero byte to a leading '1'.
//
// Inlined (rather than pulling in a dependency) so the canonical
// delegation text stays stdlib-only; swap for mr-tron/base58 once
// solana-go lands.
func base58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for n.Sign() > 0 {
		n.DivMod(n, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, c := range b { // leading zero bytes => leading '1'
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if len(out) == 0 {
		return "1"
	}
	return string(out)
}

// base58Decode is the inverse of base58Encode.
func base58Decode(s string) ([]byte, error) {
	n := new(big.Int)
	radix := big.NewInt(58)
	for _, r := range s {
		idx := strings.IndexRune(base58Alphabet, r)
		if idx < 0 {
			return nil, fmt.Errorf("wallet: invalid base58 character %q", r)
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(idx)))
	}
	var zeros int
	for i := 0; i < len(s) && s[i] == '1'; i++ {
		zeros++
	}
	return append(make([]byte, zeros), n.Bytes()...), nil
}
