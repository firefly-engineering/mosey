// Spike: render the canonical mosey delegation text exactly as the TS
// client would, sign it the way a Solana wallet's signMessage does
// (Ed25519 over the raw UTF-8 bytes), and emit {fields, content, pubkey,
// sig} as JSON for verify.go to re-render and check.
//
// Ed25519 is RFC 8032 (deterministic), so Node's crypto.sign produces a
// signature bit-identical to tweetnacl / Phantom for the same key+bytes.
// Run:  node sign.mjs | go run verify.go
import { generateKeyPairSync, sign as edSign, randomBytes } from "node:crypto";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b === 0) out = "1" + out; else break; }
  return out || "1";
}

// Raw 32-byte Ed25519 public key = last 32 bytes of the SPKI DER export.
function rawPub(publicKey) {
  const der = publicKey.export({ type: "spki", format: "der" });
  return der.subarray(der.length - 32);
}

// The canonical content grammar from docs/src/wallet-auth.md#wire-format:
// header line, blank line, then fixed-order fields, LF-joined, no trailing newline.
function render(f) {
  return [
    "mosey session authorization v1",
    "",
    `session: ${f.session}`,
    `delegator: ${f.delegator}`,
    `delegate: ${f.delegate}`,
    `caps: ${f.caps}`,
    `not-before: ${f.not_before}`,
    `not-after: ${f.not_after}`,
    `nonce: ${f.nonce}`,
  ].join("\n");
}

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const delegator = b58encode(rawPub(publicKey)); // the signer == the delegator

const caps = process.argv[2] ?? "write, resize"; // pass "view-only" to exercise the empty set
const fields = {
  session: b58encode(randomBytes(32)),
  delegator,
  delegate: b58encode(randomBytes(32)),
  caps,
  not_before: "2026-06-17T14:00:00Z",
  not_after: "2026-06-18T14:00:00Z",
  nonce: b58encode(randomBytes(16)),
};

const content = render(fields);
const sig = edSign(null, Buffer.from(content, "utf8"), privateKey);

process.stdout.write(JSON.stringify({
  fields,
  content_hex: Buffer.from(content, "utf8").toString("hex"),
  pubkey_base58: delegator,
  sig_base58: b58encode(sig),
}));
