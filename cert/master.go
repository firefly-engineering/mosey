package cert

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

// masterMnemonicEntropyBits is the entropy size for the
// master-key mnemonic. 128 bits → 12 words, 256 → 24 words. We go
// with 256 / 24 — disk space is cheap; the user is going to back
// this up once and forget it, so more bits is more durable
// security at no recurring cost.
const masterMnemonicEntropyBits = 256

// mnemonicSeedPassphrase is folded into BIP-39's PBKDF2 seed
// derivation. Empty = "no passphrase," the conventional default.
// We pin it to a domain-separated label so this seed can't be
// confused with a BIP-39 wallet seed using the same mnemonic.
const mnemonicSeedPassphrase = "mosey-cert-v1"

// masterSeedInfo is folded in after the BIP-39 seed → final
// Ed25519 seed reduction so a leaked 32-byte seed can't be
// trivially repurposed for non-mosey Ed25519 use.
const masterSeedInfo = "mosey-cert-master"

// NewMasterMnemonic generates a fresh BIP-39 mnemonic. Returns
// the mnemonic phrase plus the derived [ed25519.PrivateKey]. The
// caller is responsible for writing the phrase somewhere durable
// AND keeping it secret — losing it permanently kills the
// workspace's ability to mint new certs or revoke existing ones.
func NewMasterMnemonic() (mnemonic string, priv ed25519.PrivateKey, err error) {
	entropy, err := bip39.NewEntropy(masterMnemonicEntropyBits)
	if err != nil {
		return "", nil, fmt.Errorf("cert: master entropy: %w", err)
	}
	mnemonic, err = bip39.NewMnemonic(entropy)
	if err != nil {
		return "", nil, fmt.Errorf("cert: master mnemonic: %w", err)
	}
	priv, err = masterKeyFromMnemonic(mnemonic)
	if err != nil {
		return "", nil, err
	}
	return mnemonic, priv, nil
}

// MasterFromMnemonic re-derives the [ed25519.PrivateKey] from a
// previously-emitted mnemonic. Symmetric with NewMasterMnemonic:
// same phrase → same key.
func MasterFromMnemonic(mnemonic string) (ed25519.PrivateKey, error) {
	if mnemonic == "" {
		return nil, errors.New("cert: empty mnemonic")
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("cert: mnemonic fails BIP-39 checksum")
	}
	return masterKeyFromMnemonic(mnemonic)
}

// masterKeyFromMnemonic is the shared derivation: BIP-39 seed
// → SHA-512(seed || info) → first 32 bytes as the Ed25519 seed
// → ed25519.NewKeyFromSeed. Deterministic.
func masterKeyFromMnemonic(mnemonic string) (ed25519.PrivateKey, error) {
	seed := bip39.NewSeed(mnemonic, mnemonicSeedPassphrase)
	h := sha512.New()
	h.Write(seed)
	h.Write([]byte(masterSeedInfo))
	sum := h.Sum(nil)
	return ed25519.NewKeyFromSeed(sum[:ed25519.SeedSize]), nil
}

// MasterPublicKey returns the Ed25519 public half of priv. Trivial
// wrapper that documents the type cast — callers store the public
// key with each vterm so verifiers can authenticate certs without
// the master mnemonic.
func MasterPublicKey(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}
