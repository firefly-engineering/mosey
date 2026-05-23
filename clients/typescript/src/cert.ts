// Cert verification — port of cert/cert.go Verify on the Go side.
//
// Step-for-step:
//   1. Ed25519.verify(masterPub, Cert.content, Cert.signature)
//   2. Decode SignedCertContent from Cert.content
//   3. workspace_id must match the verifier's expected value
//   4. `now` must fall in [not_before, not_after]
//   5. Serial must not be in the revoked set
//
// On success returns a Claim. On failure throws a CertError with
// the same `cert:` prefix the Go side uses, so cross-language
// debugging surfaces consistent error text.

import {
  ed25519Verify,
  ED25519_PUBLIC_KEY_SIZE,
} from "./crypto.js";
import {
  type Cert,
  decodeSignedCertContent,
  type Timestamp,
} from "./proto.js";

// Capability bit layout matches api/cert.proto:
//   bit 0 = Owner, bit 1 = Write, bit 2 = Resize
// Owner implies Write + Resize at the consumer (Identity) layer;
// these bitmasks are the raw form on the wire.
export const CapsBitOwner = 1;
export const CapsBitWrite = 2;
export const CapsBitResize = 4;

// Claim is the high-level result of a successful Verify. Mirrors
// cert.Claim in cert/cert.go.
export interface Claim {
  agentId: string;
  peerPubkey: Uint8Array;
  label: string;
  capsBits: number;
  notBefore: Date;
  notAfter: Date;
  serial: string;
  workspaceId: string;
}

// Convenience accessors mirroring the Claim methods on the Go side.
// Owner does NOT imply Write/Resize here — that promotion happens
// at the Identity layer (see cert-auth.ts).
export const hasOwner = (c: Claim): boolean => (c.capsBits & CapsBitOwner) !== 0;
export const hasWrite = (c: Claim): boolean => (c.capsBits & CapsBitWrite) !== 0;
export const hasResize = (c: Claim): boolean => (c.capsBits & CapsBitResize) !== 0;

// VerifyOptions matches the cert.VerifyOptions struct: master pubkey
// (required), expected workspace (required — empty is rejected),
// optional now-override for tests, and an optional revoked-serial
// set.
export interface VerifyOptions {
  masterPub: Uint8Array;
  workspaceId: string;
  now?: Date;
  revoked?: ReadonlySet<string>;
}

// CertError is the thrown shape on any verification failure.
// `reason` is one of a fixed set of tags so callers can react
// programmatically without parsing message strings.
export type CertErrorReason =
  | "invalid-signature"
  | "expired"
  | "wrong-workspace"
  | "revoked"
  | "malformed";

export class CertError extends Error {
  constructor(public readonly reason: CertErrorReason, message: string) {
    super(`cert: ${message}`);
    this.name = "CertError";
  }
}

// verifyCert returns a Claim on success, throws a CertError on
// failure. Matches cert/cert.go Verify semantics exactly — the Go
// test suite is the cross-language contract.
export async function verifyCert(
  cert: Cert,
  opts: VerifyOptions,
): Promise<Claim> {
  if (opts.masterPub.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new CertError(
      "malformed",
      `master public key length ${opts.masterPub.length}, want ${ED25519_PUBLIC_KEY_SIZE}`,
    );
  }

  const sigOK = await ed25519Verify(opts.masterPub, cert.content, cert.signature);
  if (!sigOK) {
    throw new CertError(
      "invalid-signature",
      "signature does not match master public key",
    );
  }

  let scc;
  try {
    scc = decodeSignedCertContent(cert.content);
  } catch (err) {
    throw new CertError(
      "malformed",
      `unmarshal content: ${(err as Error).message}`,
    );
  }

  const now = opts.now ?? new Date();
  const notBefore = timestampToDate(scc.notBefore);
  const notAfter = timestampToDate(scc.notAfter);
  if (now < notBefore || now > notAfter) {
    throw new CertError(
      "expired",
      `not within validity window: now=${now.toISOString()} not_before=${notBefore.toISOString()} not_after=${notAfter.toISOString()}`,
    );
  }

  // Workspace check: Go's Verify only enforces when opts.WorkspaceID
  // is non-empty. We require it as a public API contract — a
  // verifier without an expected workspace is a configuration error,
  // not a feature.
  if (opts.workspaceId === "") {
    throw new CertError("malformed", "VerifyOptions.workspaceId is required");
  }
  if (scc.workspaceId !== opts.workspaceId) {
    throw new CertError(
      "wrong-workspace",
      `workspace_id mismatch: got ${JSON.stringify(scc.workspaceId)} want ${JSON.stringify(opts.workspaceId)}`,
    );
  }

  if (opts.revoked && opts.revoked.has(scc.serial)) {
    throw new CertError("revoked", `serial is revoked: ${scc.serial}`);
  }

  if (scc.peerPubkey.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new CertError(
      "malformed",
      `peer public key length ${scc.peerPubkey.length}, want ${ED25519_PUBLIC_KEY_SIZE}`,
    );
  }

  return {
    agentId: scc.agentId,
    peerPubkey: scc.peerPubkey,
    label: scc.label,
    capsBits: scc.capsBits,
    notBefore,
    notAfter,
    serial: scc.serial,
    workspaceId: scc.workspaceId,
  };
}

// timestampToDate folds google.protobuf.Timestamp into a JS Date.
// JS Date is millisecond resolution — the sub-millisecond half of
// `nanos` is silently dropped. Mosey certs don't use sub-millisecond
// timestamps in practice, so this is lossless for any real cert.
function timestampToDate(ts: Timestamp): Date {
  const ms = Number(ts.seconds) * 1000 + Math.floor(ts.nanos / 1_000_000);
  return new Date(ms);
}
