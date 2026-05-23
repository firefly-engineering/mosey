// WebCrypto wrappers for the PSK auth handshake. All primitives
// come from the host environment — `crypto.subtle` for HKDF + HMAC,
// `crypto.getRandomValues` for nonces. No external dependency.
//
// HKDF parameters and MAC labels must match
// `internal/auth/psk.go`:
//   info  = "mosey.v1.psk"
//   macLabelServer = "mosey-auth-v1:S"
//   macLabelClient = "mosey-auth-v1:C"
// Output of derivePSKKey is exactly 32 bytes.

export const PSK_HKDF_INFO = "mosey.v1.psk";
export const MAC_LABEL_SERVER = "mosey-auth-v1:S";
export const MAC_LABEL_CLIENT = "mosey-auth-v1:C";
export const NONCE_SIZE = 32;

// derivePSKKey runs HKDF-SHA256 with an empty salt and the
// mosey.v1.psk info label to expand the plaintext secret into a
// 32-byte HMAC key. Mirrors `derivePSKKey` in psk.go exactly.
export async function derivePSKKey(secret: string): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    asBufferSource(new TextEncoder().encode(secret)),
    "HKDF",
    false,
    ["deriveBits"],
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(PSK_HKDF_INFO),
    },
    keyMaterial,
    32 * 8,
  );
  return new Uint8Array(derived);
}

// hmacSHA256 computes HMAC-SHA256(key, concat(parts)). Multi-arg
// signature mirrors how psk.go composes the MAC body: label,
// nonce, nonce. No need to materialize the concatenation in the
// caller.
export async function hmacSHA256(key: Uint8Array, ...parts: Uint8Array[]): Promise<Uint8Array> {
  const macKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  let total = 0;
  for (const p of parts) total += p.length;
  const data = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    data.set(p, off);
    off += p.length;
  }
  const sig = await crypto.subtle.sign("HMAC", macKey, asBufferSource(data));
  return new Uint8Array(sig);
}

// asBufferSource bridges TS 5.7+'s strict generic `Uint8Array`
// type (which distinguishes ArrayBuffer-backed from
// SharedArrayBuffer-backed) and WebCrypto's `BufferSource`
// parameter, which is strict to ArrayBuffer-backed. Every
// Uint8Array in this codebase is freshly allocated or comes from
// TextEncoder — both ArrayBuffer-backed — so the cast is sound at
// runtime. The cast is centralized here so future audits have one
// place to check.
function asBufferSource(b: Uint8Array): BufferSource {
  return b as unknown as BufferSource;
}

// constantTimeEqual avoids early-exit comparison so an attacker
// observing timing can't recover which prefix of the MAC matched.
// Length mismatch returns false immediately because it doesn't
// leak content — only that the lengths differ, which a peer
// controlling the message can already see.
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

// randomNonce returns NONCE_SIZE bytes of cryptographically random
// data. Uses the standard browser / Node 18+ crypto API.
export function randomNonce(): Uint8Array {
  const out = new Uint8Array(NONCE_SIZE);
  crypto.getRandomValues(out);
  return out;
}

// labelBytes converts a UTF-8 label into the bytes that prepend
// the MAC input. Exposed so tests + transcript debugging can
// reproduce the exact byte sequence the MAC covers.
export function labelBytes(label: string): Uint8Array {
  return new TextEncoder().encode(label);
}

// ────────────────────────────────────────────────────────────────
// Ed25519 — used by the cert auth path (see cert.ts, cert-auth.ts).
//
// Implementation: WebCrypto subtle's "Ed25519" algorithm. Available
// in Chrome 113+, Firefox 130+, Safari 17+, and Node 18.4+. Keeps
// the package zero-dependency (matches the README promise).
//
// Key formats match the Go side:
//   - public key:  32 raw bytes (Ed25519 verifying key)
//   - private key: 64 bytes — 32-byte seed + 32-byte public key, the
//                   format used by Go's ed25519.PrivateKey. The first
//                   32 bytes are imported as the "raw" PKCS#8 seed
//                   for subtle.
// ────────────────────────────────────────────────────────────────

export const ED25519_PUBLIC_KEY_SIZE = 32;
export const ED25519_PRIVATE_KEY_SIZE = 64;
export const ED25519_SIGNATURE_SIZE = 64;

// ed25519Verify returns true iff `signature` is a valid Ed25519
// signature of `message` under `publicKey`. Throws on malformed
// key (wrong length, not importable). Verification failures return
// false rather than throwing — callers translate that into their
// own auth-rejection error.
export async function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  if (publicKey.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new Error(`mosey/crypto: Ed25519 public key length ${publicKey.length}, want ${ED25519_PUBLIC_KEY_SIZE}`);
  }
  if (signature.length !== ED25519_SIGNATURE_SIZE) {
    return false;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    asBufferSource(publicKey),
    "Ed25519",
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "Ed25519",
    key,
    asBufferSource(signature),
    asBufferSource(message),
  );
}

// ed25519Sign signs `message` with `privateKey` and returns a
// 64-byte signature. `privateKey` is the Go-style 64-byte form
// (32-byte seed || 32-byte public key); only the seed half is
// imported into subtle. Throws on malformed key.
export async function ed25519Sign(
  privateKey: Uint8Array,
  message: Uint8Array,
): Promise<Uint8Array> {
  if (privateKey.length !== ED25519_PRIVATE_KEY_SIZE) {
    throw new Error(`mosey/crypto: Ed25519 private key length ${privateKey.length}, want ${ED25519_PRIVATE_KEY_SIZE}`);
  }
  const seed = privateKey.subarray(0, 32);
  // WebCrypto subtle wants the seed wrapped in a minimal PKCS#8
  // envelope. The fixed prefix below is the OneAsymmetricKey
  // (RFC 5958) header for Ed25519 with an inline OCTET STRING of
  // length 32 — i.e. exactly the seed format Go exposes as the
  // first half of its ed25519.PrivateKey.
  const pkcs8 = wrapEd25519SeedInPKCS8(seed);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    asBufferSource(pkcs8),
    "Ed25519",
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("Ed25519", key, asBufferSource(message));
  return new Uint8Array(sig);
}

// wrapEd25519SeedInPKCS8 builds the minimal PKCS#8 / OneAsymmetricKey
// DER envelope expected by subtle.importKey("pkcs8", ..., "Ed25519").
// Fixed header (16 bytes) covers the version, AlgorithmIdentifier
// (id-Ed25519 = 1.3.101.112), and OCTET STRING tag/length for the
// 32-byte inner key bytes. See RFC 8410 §7 for the structure.
function wrapEd25519SeedInPKCS8(seed: Uint8Array): Uint8Array {
  const prefix = new Uint8Array([
    0x30, 0x2e, // SEQUENCE, length 46
    0x02, 0x01, 0x00, // INTEGER version 0
    0x30, 0x05, // SEQUENCE (AlgorithmIdentifier), length 5
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
    0x04, 0x22, // OCTET STRING, length 34
    0x04, 0x20, // (inner) OCTET STRING, length 32
  ]);
  const out = new Uint8Array(prefix.length + seed.length);
  out.set(prefix, 0);
  out.set(seed, prefix.length);
  return out;
}
