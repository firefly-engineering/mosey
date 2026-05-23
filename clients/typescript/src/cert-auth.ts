// Symmetric cert handshake — port of auth/cert.go runHandshake
// with clientFirst=true (TS is always the dialing side).
//
// Flow:
//   1. Generate 32-byte nonce (myNonce).
//   2. Send CertHello { localCert, myNonce }.
//   3. Read peer CertHello.
//   4. Verify peer cert against masterPub + workspaceId (+ revoked).
//   5. Sign "mosey-cert-v1" || peerHello.nonce with localPriv.
//   6. Send SignedNonce { mySig }.
//   7. Read peer SignedNonce.
//   8. Verify Ed25519(peerClaim.peerPubkey, "mosey-cert-v1" || myNonce, peerSig).
//   9. Read ackOK byte (0x01) from the server.
//   10. Return Identity { label, caps } from peerClaim.
//
// Failures throw with the "mosey/auth(cert): " prefix mirroring
// the Go side's errPrefixCert.

import {
  AckOK,
} from "./auth.js";
import {
  type Claim,
  type VerifyOptions,
  verifyCert,
} from "./cert.js";
import {
  ED25519_PUBLIC_KEY_SIZE,
  ed25519Sign,
  ed25519Verify,
  randomNonce,
} from "./crypto.js";
import {
  type Cert,
  decodeCertHandshakeMessage,
  encodeCertHelloMessage,
  encodeCertProofMessage,
} from "./proto.js";
import { Stream } from "./transport.js";

/**
 * certProofLabel is the fixed prefix Ed25519-signed during the
 * handshake. It separates the cert nonce signature from any other
 * signature an Ed25519 key might produce — without this label, a
 * signature collected from a different context could be replayed
 * as a handshake proof. Must match `certProofLabel` in
 * auth/cert.go.
 */
export const CERT_PROOF_LABEL = "mosey-cert-v1";

/**
 * CERT_NONCE_SIZE is the per-side challenge size. Matches
 * `certNonceSize` in auth/cert.go; the constant is exported so a
 * future bump on either side stays linkable.
 */
export const CERT_NONCE_SIZE = 32;

export interface CertAuthOptions {
  /** Master public key (32 raw bytes) used to verify the peer's cert. */
  masterPub: Uint8Array;
  /** Workspace identifier the peer's cert must match. */
  workspaceId: string;
  /** Local cert (decoded api.Cert). Sent to the peer in CertHello. */
  localCert: Cert;
  /**
   * Local Ed25519 private key (64-byte Go form: seed || public).
   * Public half must match localCert's embedded peer_pubkey — the
   * caller is expected to have verified that at config time (see
   * client.ts).
   */
  localPriv: Uint8Array;
  /**
   * Optional set of revoked cert serials. Caller can swap this set
   * on its own; we snapshot the reference at call time.
   */
  revoked?: ReadonlySet<string>;
}

export interface Identity {
  label: string;
  caps: {
    owner: boolean;
    write: boolean;
    resize: boolean;
  };
}

/**
 * runCertHandshake drives the symmetric cert handshake to
 * completion on an already-open auth stream. Closes the stream on
 * success; throws on any failure with a "mosey/auth(cert): "
 * prefix.
 */
export async function runCertHandshake(
  authStream: Stream,
  opts: CertAuthOptions,
): Promise<Identity> {
  // 1. Local nonce.
  const myNonce = randomNonce();
  if (myNonce.length !== CERT_NONCE_SIZE) {
    // randomNonce returns NONCE_SIZE = 32, same as CERT_NONCE_SIZE,
    // but the cert path is independent enough to be explicit.
    throw new Error(
      `mosey/auth(cert): local nonce length ${myNonce.length}, want ${CERT_NONCE_SIZE}`,
    );
  }

  // 2. Send our CertHello.
  authStream.sendFramed(
    encodeCertHelloMessage({ cert: opts.localCert, nonce: myNonce }),
  );

  // 3. Read peer's CertHello.
  const helloFrame = await authStream.readFramed();
  const helloDecoded = decodeCertHandshakeMessage(helloFrame);
  if (!helloDecoded.hello) {
    throw new Error(
      "mosey/auth(cert): expected CertHello, got " + summarize(helloDecoded),
    );
  }
  const peerHello = helloDecoded.hello;

  // 4. Verify peer cert.
  let peerClaim: Claim;
  try {
    const verifyOpts: VerifyOptions = {
      masterPub: opts.masterPub,
      workspaceId: opts.workspaceId,
    };
    if (opts.revoked) verifyOpts.revoked = opts.revoked;
    peerClaim = await verifyCert(peerHello.cert, verifyOpts);
  } catch (err) {
    // Re-wrap with the auth-layer prefix so consumers see the same
    // shape they'd see from the PSK path.
    throw new Error(`mosey/auth(cert): peer cert: ${(err as Error).message}`);
  }
  if (peerHello.nonce.length !== CERT_NONCE_SIZE) {
    throw new Error(
      `mosey/auth(cert): peer nonce length ${peerHello.nonce.length}, want ${CERT_NONCE_SIZE}`,
    );
  }

  // 5. Sign the PEER's nonce.
  const mySig = await ed25519Sign(
    opts.localPriv,
    concat(textBytes(CERT_PROOF_LABEL), peerHello.nonce),
  );

  // 6. Send our SignedNonce.
  authStream.sendFramed(encodeCertProofMessage({ signature: mySig }));

  // 7. Read peer's SignedNonce.
  const proofFrame = await authStream.readFramed();
  const proofDecoded = decodeCertHandshakeMessage(proofFrame);
  if (!proofDecoded.proof) {
    throw new Error(
      "mosey/auth(cert): expected SignedNonce, got " + summarize(proofDecoded),
    );
  }

  // 8. Verify peer's signature over OUR nonce against peerClaim.peerPubkey.
  if (peerClaim.peerPubkey.length !== ED25519_PUBLIC_KEY_SIZE) {
    // verifyCert already enforced this, but keep the assertion
    // local to make the verify call's contract obvious.
    throw new Error(
      `mosey/auth(cert): peer cert pubkey length ${peerClaim.peerPubkey.length}, want ${ED25519_PUBLIC_KEY_SIZE}`,
    );
  }
  const sigOK = await ed25519Verify(
    peerClaim.peerPubkey,
    concat(textBytes(CERT_PROOF_LABEL), myNonce),
    proofDecoded.proof.signature,
  );
  if (!sigOK) {
    throw new Error("mosey/auth(cert): peer proof signature invalid");
  }

  // 9. Wait for the ackOK byte.
  const ack = await readOneByte(authStream);
  if (ack !== AckOK) {
    throw new Error(
      `mosey/auth(cert): server sent unexpected ack 0x${ack.toString(16)}`,
    );
  }
  authStream.close();

  // 10. Promote caps the same way auth/cert.go's claimToIdentity does.
  const owner = (peerClaim.capsBits & 1) !== 0;
  const write = (peerClaim.capsBits & 2) !== 0;
  const resize = (peerClaim.capsBits & 4) !== 0;
  return {
    label: peerClaim.label,
    caps: {
      owner,
      write: write || owner,
      resize: resize || owner,
    },
  };
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function textBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function summarize(decoded: Record<string, unknown>): string {
  const keys = Object.keys(decoded);
  return keys.length === 0 ? "<empty>" : keys.join(",");
}

/**
 * readOneByte resolves with the next byte from `stream`. Same
 * shape as the PSK ackOK helper — duplicated here so cert-auth
 * doesn't depend on PSK auth's internals.
 */
function readOneByte(stream: Stream): Promise<number> {
  return new Promise((resolve, reject) => {
    let done = false;
    stream.onData((chunk: Uint8Array) => {
      if (done) return;
      done = true;
      if (chunk.length === 0) {
        reject(new Error("mosey/auth(cert): server closed before ack"));
        return;
      }
      resolve(chunk[0]!);
    });
  });
}
