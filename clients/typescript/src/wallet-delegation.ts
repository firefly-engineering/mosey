// Canonical delegation text for wallet auth — the TS counterpart of the
// Go wallet package. The rendered bytes MUST be byte-identical to Go's
// (wallet.Fields.Render); the shared golden vector in
// wallet/testdata/delegation-vectors.json pins this across both.
import { ed25519Verify } from "./crypto.js";

// Capability bits. No "owner" bit: ownership is the structural session
// owner, and the owner implicitly holds every cap.
export const CapWrite = 1;
export const CapResize = 2;
export const CapForge = 4;
export const AllCaps = CapWrite | CapResize | CapForge;

const CONTENT_HEADER = "mosey session authorization v1";
const NONCE_SIZE = 16;
const PUBKEY_SIZE = 32;
const TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = B58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return out === "" ? "1" : out;
}

export function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const ch of s) {
    const idx = B58_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`wallet: invalid base58 character ${JSON.stringify(ch)}`);
    n = n * 58n + BigInt(idx);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (let i = 0; i < s.length && s[i] === "1"; i++) bytes.unshift(0);
  return new Uint8Array(bytes);
}

// capsToString renders the present bits in the fixed order
// "write, resize, forge", with the empty set as "view-only".
export function capsToString(caps: number): string {
  const parts: string[] = [];
  if (caps & CapWrite) parts.push("write");
  if (caps & CapResize) parts.push("resize");
  if (caps & CapForge) parts.push("forge");
  return parts.length === 0 ? "view-only" : parts.join(", ");
}

// parseCaps is the strict inverse of capsToString: only the exact
// canonical rendering is accepted.
export function parseCaps(s: string): number {
  if (s === "view-only") return 0;
  let caps = 0;
  for (const tok of s.split(", ")) {
    switch (tok) {
      case "write":
        caps |= CapWrite;
        break;
      case "resize":
        caps |= CapResize;
        break;
      case "forge":
        caps |= CapForge;
        break;
      default:
        throw new Error(`wallet: invalid caps token ${JSON.stringify(tok)}`);
    }
  }
  if (capsToString(caps) !== s) throw new Error(`wallet: non-canonical caps ${JSON.stringify(s)}`);
  return caps;
}

// formatTime renders a Date as the canonical timestamp: strict RFC3339,
// UTC, seconds precision, trailing "Z".
export function formatTime(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export interface Fields {
  session: Uint8Array;
  delegator: Uint8Array;
  delegate: Uint8Array;
  caps: number;
  notBefore: string; // canonical RFC3339 (see formatTime)
  notAfter: string;
  nonce: Uint8Array;
}

// renderContent produces the canonical UTF-8 bytes a wallet signs.
export function renderContent(f: Fields): Uint8Array {
  const lines = [
    CONTENT_HEADER,
    "",
    `session: ${base58Encode(f.session)}`,
    `delegator: ${base58Encode(f.delegator)}`,
    `delegate: ${base58Encode(f.delegate)}`,
    `caps: ${capsToString(f.caps)}`,
    `not-before: ${f.notBefore}`,
    `not-after: ${f.notAfter}`,
    `nonce: ${base58Encode(f.nonce)}`,
  ];
  return new TextEncoder().encode(lines.join("\n"));
}

// parseContent strictly parses canonical content back into Fields.
export function parseContent(content: Uint8Array): Fields {
  const lines = new TextDecoder().decode(content).split("\n");
  if (lines.length !== 9) throw new Error(`wallet: delegation has ${lines.length} lines, want 9`);
  if (lines[0] !== CONTENT_HEADER) throw new Error(`wallet: bad delegation header`);
  if (lines[1] !== "") throw new Error("wallet: delegation line 2 must be blank");

  const value = (i: number, key: string): string => {
    const prefix = `${key}: `;
    const line = lines[i]!;
    if (!line.startsWith(prefix)) throw new Error(`wallet: line ${i + 1} is not ${key}`);
    return line.slice(prefix.length);
  };
  const key32 = (i: number, name: string): Uint8Array => {
    const b = base58Decode(value(i, name));
    if (b.length !== PUBKEY_SIZE) throw new Error(`wallet: ${name} is ${b.length} bytes, want 32`);
    return b;
  };
  const ts = (i: number, name: string): string => {
    const v = value(i, name);
    if (!TS_RE.test(v)) throw new Error(`wallet: non-canonical timestamp ${JSON.stringify(v)}`);
    return v;
  };

  const session = key32(2, "session");
  const delegator = key32(3, "delegator");
  const delegate = key32(4, "delegate");
  const caps = parseCaps(value(5, "caps"));
  const notBefore = ts(6, "not-before");
  const notAfter = ts(7, "not-after");
  const nonce = base58Decode(value(8, "nonce"));
  if (nonce.length !== NONCE_SIZE) throw new Error(`wallet: nonce is ${nonce.length} bytes, want 16`);
  return { session, delegator, delegate, caps, notBefore, notAfter, nonce };
}

export interface Delegation {
  content: Uint8Array;
  signature: Uint8Array;
}

// verifyDelegation parses the content and checks the signature against
// the delegator named inside.
export async function verifyDelegation(d: Delegation): Promise<boolean> {
  const f = parseContent(d.content);
  return ed25519Verify(f.delegator, d.content, d.signature);
}
