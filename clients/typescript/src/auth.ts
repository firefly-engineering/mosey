// PSK auth handshake — three messages: ClientHello / ServerProof /
// ClientProof. Mirrors `internal/auth/psk.go` on the Go side.
//
// Flow:
//   1. Client sends ClientHello { nonce_c, label }
//   2. Server replies ServerProof { nonce_s, mac_s }
//      mac_s = HMAC(key, "mosey-auth-v1:S" || nonce_c || nonce_s)
//   3. Client sends ClientProof { mac_c }
//      mac_c = HMAC(key, "mosey-auth-v1:C" || nonce_s || nonce_c)
//
// After step 3 the server writes a single ackOK byte (0x01) and
// closes the auth stream; the client opens application streams
// (PTY / control) on the same WebSocket peer-token and the
// auth-wrap layer correlates them via Sec-WebSocket-Protocol.

import {
  constantTimeEqual,
  derivePSKKey,
  hmacSHA256,
  labelBytes,
  MAC_LABEL_CLIENT,
  MAC_LABEL_SERVER,
  NONCE_SIZE,
  randomNonce,
} from "./crypto.js";
import {
  decodeAuthMessage,
  encodeAuthClientHello,
  encodeAuthClientProof,
} from "./proto.js";
import { Stream } from "./transport.js";

/**
 * AckOK is the one byte the server writes on the auth stream
 * after a successful handshake; the client blocks on it before
 * opening the application stream. Without this sync byte a fast
 * client could race past the server's identity-store write and
 * get refused by the auth-wrap gate.
 */
export const AckOK = 0x01;

export interface PSKAuthOptions {
  /** Plaintext shared secret. Same value the launcher sees as `--secret`. */
  secret: string;
  /**
   * Optional role label sent in ClientHello. Empty / unset maps to
   * the server's owner entry — matches Go-side default.
   */
  label?: string;
}

/**
 * runPSKHandshake drives the three-message PSK handshake to
 * completion on an already-open auth stream. Closes the stream on
 * success (it has no application data) and throws on any failure.
 *
 * The caller is responsible for opening `/mosey/auth/1.0.0` on the
 * WebSocket transport with the same peer token they'll use for
 * subsequent application streams.
 */
export async function runPSKHandshake(
  authStream: Stream,
  opts: PSKAuthOptions,
): Promise<void> {
  const key = await derivePSKKey(opts.secret);
  const label = opts.label ?? "";

  // 1. Send ClientHello.
  const nonceC = randomNonce();
  authStream.sendFramed(encodeAuthClientHello({ nonce: nonceC, label }));

  // 2. Receive ServerProof and verify its MAC.
  const proofMsg = await authStream.readFramed();
  const decoded = decodeAuthMessage(proofMsg);
  if (!decoded.serverProof) {
    throw new Error("mosey/auth(psk): expected ServerProof, got " + summarize(decoded));
  }
  const { nonce: nonceS, mac: macS } = decoded.serverProof;
  if (nonceS.length !== NONCE_SIZE) {
    throw new Error(`mosey/auth(psk): server nonce length ${nonceS.length}, want ${NONCE_SIZE}`);
  }
  const expectedServerMac = await hmacSHA256(
    key,
    labelBytes(MAC_LABEL_SERVER),
    nonceC,
    nonceS,
  );
  if (!constantTimeEqual(macS, expectedServerMac)) {
    throw new Error("mosey/auth(psk): server MAC mismatch (wrong secret or replay)");
  }

  // 3. Compute and send our ClientProof.
  const macC = await hmacSHA256(
    key,
    labelBytes(MAC_LABEL_CLIENT),
    nonceS,
    nonceC,
  );
  authStream.sendFramed(encodeAuthClientProof({ mac: macC }));

  // 4. Wait for ackOK byte. The server writes 0x01 once it has
  //    recorded our identity in its per-peer-token map. Reading it
  //    here ensures that by the time we open the PTY stream the
  //    server's auth gate will let it through.
  //
  //    On the WS backend the ackOK arrives as a one-byte binary
  //    frame. We read it via the next data event by temporarily
  //    flipping to data mode — easier than threading a "raw byte"
  //    path through readFramed.
  const ack = await readOneByte(authStream);
  if (ack !== AckOK) {
    throw new Error(`mosey/auth(psk): server sent unexpected ack 0x${ack.toString(16)}`);
  }

  // Close the auth stream — its work is done. Application streams
  // use fresh WebSocket connections with the same peer token.
  authStream.close();
}

/**
 * readOneByte resolves with the next byte from `stream`. Used to
 * consume the server's ackOK signal. Switches the stream into
 * data-handler mode for the single read, then surrenders.
 */
function readOneByte(stream: Stream): Promise<number> {
  return new Promise((resolve, reject) => {
    let done = false;
    stream.onData((chunk: Uint8Array) => {
      if (done) return;
      done = true;
      if (chunk.length === 0) {
        reject(new Error("mosey/auth(psk): server closed before ack"));
        return;
      }
      resolve(chunk[0]!);
    });
  });
}

function summarize(decoded: Record<string, unknown>): string {
  const keys = Object.keys(decoded);
  return keys.length === 0 ? "<empty>" : keys.join(",");
}
