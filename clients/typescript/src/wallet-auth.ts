// Wallet handshake — port of the client half of auth/wallet.go.
//
// Mutual but asymmetric: the server proves control of the session key,
// the client (always the dialer here) proves control of the connection
// key K_c and presents the delegation chain that authorizes it.
//
// Flow:
//   1. Generate 32-byte nonceC.
//   2. Send WalletHello { connPub, nonceC, delegationChain }.
//   3. Read WalletChallenge { sessionKey, nonceS, serverSig }.
//   4. Verify serverSig over "mosey-wallet-v1:server" ‖ nonceC ‖ nonceS ‖ sessionKey.
//   5. If expectSession is set, require sessionKey == expectSession.
//   6. Sign "mosey-wallet-v1:client" ‖ nonceS ‖ nonceC ‖ sessionKey with K_c.
//   7. Send WalletProof { clientSig }.
//   8. Read ackOK byte (0x01).
//
// Failures throw with the "mosey/auth(wallet): " prefix mirroring the
// Go side's errPrefixWallet.

import { AckOK } from "./auth.js";
import { type Identity } from "./cert-auth.js";
import {
  ED25519_PRIVATE_KEY_SIZE,
  ED25519_PUBLIC_KEY_SIZE,
  constantTimeEqual,
  ed25519Sign,
  ed25519Verify,
  randomNonce,
} from "./crypto.js";
import {
  type Delegation,
  decodeWalletHandshakeMessage,
  encodeWalletHelloMessage,
  encodeWalletProofMessage,
} from "./proto.js";
import { Stream } from "./transport.js";
import { CapResize, CapWrite, base58Encode, parseContent } from "./wallet-delegation.js";

const WALLET_NONCE_SIZE = 32;
const SERVER_LABEL = "mosey-wallet-v1:server";
const CLIENT_LABEL = "mosey-wallet-v1:client";

export interface WalletHandshakeOptions {
  // connKey is the 64-byte Ed25519 private key for the connection key
  // K_c (Go form: seed ‖ public). The chain's leaf must delegate to its
  // public half.
  connKey: Uint8Array;
  // delegationChain authorizes connKey, root → leaf.
  delegationChain: Delegation[];
  // expectSession, when set, is the 32-byte session identity the dialer
  // intends to reach; the handshake fails if the server proves another.
  expectSession?: Uint8Array;
}

export async function runWalletHandshake(
  authStream: Stream,
  opts: WalletHandshakeOptions,
): Promise<Identity> {
  if (opts.connKey.length !== ED25519_PRIVATE_KEY_SIZE) {
    throw new Error(
      `mosey/auth(wallet): connKey must be ${ED25519_PRIVATE_KEY_SIZE} bytes, got ${opts.connKey.length}`,
    );
  }
  const connPub = opts.connKey.slice(32, 64);
  const nonceC = randomNonce();

  authStream.sendFramed(
    encodeWalletHelloMessage({
      clientPubkey: connPub,
      nonceC,
      delegationChain: opts.delegationChain,
    }),
  );

  const decoded = decodeWalletHandshakeMessage(await authStream.readFramed());
  if (!decoded.challenge) {
    throw new Error(`mosey/auth(wallet): expected challenge, got ${summarize(decoded)}`);
  }
  const { sessionKey, nonceS, serverSig } = decoded.challenge;
  if (sessionKey.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new Error(`mosey/auth(wallet): session_key length ${sessionKey.length}`);
  }
  if (nonceS.length !== WALLET_NONCE_SIZE) {
    throw new Error(`mosey/auth(wallet): nonce_s length ${nonceS.length}`);
  }

  const serverOK = await ed25519Verify(
    sessionKey,
    transcript(SERVER_LABEL, nonceC, nonceS, sessionKey),
    serverSig,
  );
  if (!serverOK) {
    throw new Error("mosey/auth(wallet): server proof signature invalid");
  }
  if (opts.expectSession && !constantTimeEqual(sessionKey, opts.expectSession)) {
    throw new Error(
      `mosey/auth(wallet): server presented session ${base58Encode(sessionKey)}, expected ${base58Encode(opts.expectSession)}`,
    );
  }

  const clientSig = await ed25519Sign(
    opts.connKey,
    transcript(CLIENT_LABEL, nonceS, nonceC, sessionKey),
  );
  authStream.sendFramed(encodeWalletProofMessage({ clientSig }));

  const ack = await readOneByte(authStream);
  if (ack !== AckOK) {
    throw new Error(`mosey/auth(wallet): server sent unexpected ack 0x${ack.toString(16)}`);
  }
  authStream.close();

  return leafIdentity(sessionKey, opts.delegationChain);
}

function transcript(label: string, a: Uint8Array, b: Uint8Array, sessionID: Uint8Array): Uint8Array {
  const labelBytes = new TextEncoder().encode(label);
  const out = new Uint8Array(labelBytes.length + a.length + b.length + sessionID.length);
  let off = 0;
  for (const part of [labelBytes, a, b, sessionID]) {
    out.set(part, off);
    off += part.length;
  }
  return out;
}

// leafIdentity is a best-effort local label: the server's view is
// authoritative. It reflects the session reached and the caps the leaf
// delegation claims (owner status is unknown without the snapshot).
function leafIdentity(sessionKey: Uint8Array, chain: Delegation[]): Identity {
  let caps = 0;
  const leaf = chain[chain.length - 1];
  if (leaf) {
    try {
      caps = parseContent(leaf.content).caps;
    } catch {
      // leave caps at 0 for the display hint
    }
  }
  return {
    label: `wallet:${base58Encode(sessionKey)}`,
    caps: {
      owner: false,
      write: (caps & CapWrite) !== 0,
      resize: (caps & CapResize) !== 0,
    },
  };
}

function summarize(decoded: Record<string, unknown>): string {
  const keys = Object.keys(decoded);
  return keys.length === 0 ? "<empty>" : keys.join(",");
}

// readOneByte resolves with the next byte, or rejects if the server
// drops the stream first. Unlike cert/PSK — which only await the ack
// after a fully successful handshake — wallet auth can be rejected at
// the ack stage (the server's authorization runs after it reads the
// client proof), so closure must be detected here.
function readOneByte(stream: Stream): Promise<number> {
  return new Promise((resolve, reject) => {
    let done = false;
    const settle = (fn: () => void) => {
      if (done) return;
      done = true;
      fn();
    };
    stream.onData((chunk: Uint8Array) => {
      settle(() => {
        if (chunk.length === 0) {
          reject(new Error("mosey/auth(wallet): server closed before ack"));
        } else {
          resolve(chunk[0]!);
        }
      });
    });
    stream.whenClosed().then((err) => settle(() => reject(err)));
  });
}
