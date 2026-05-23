// MoseyClient — the high-level surface most callers want. Wraps:
//
//   1. Auth handshake on /mosey/auth/1.0.0 (PSK or cert)
//   2. PTY byte stream on /mosey/pty/1.0.0
//   3. Optional control stream on /mosey/control/1.0.0 (for resize)
//
// Usage shape:
//
//   const client = await MoseyClient.connect({
//     endpoint: "wss://host:8443",
//     auth: { type: "psk", secret: "hunter2" },
//   });
//
//   client.onData((bytes) => term.write(bytes));
//   term.onData((str) => client.write(new TextEncoder().encode(str)));
//   term.onResize(({cols, rows}) => client.resize(cols, rows));
//
//   await client.close();

import { PSKAuthOptions, runPSKHandshake } from "./auth.js";
import { runCertHandshake } from "./cert-auth.js";
import { verifyCert } from "./cert.js";
import { ED25519_PRIVATE_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE } from "./crypto.js";
import {
  type Cert,
  decodeCert,
  encodeControlResize,
} from "./proto.js";
import {
  mintPeerToken,
  ProtoAuth,
  ProtoControl,
  ProtoPTY,
  Stream,
} from "./transport.js";

/** PSK auth — match the launcher's `--secret`. */
export interface PSKAuthConfig {
  type: "psk";
  secret: string;
  /** Optional role label (defaults to owner-equivalent). */
  label?: string;
}

/**
 * CertAuth — workspace-cert based auth. The browser equivalent of
 * `mosey launch --cert=... --key=... --master-pub=... --workspace=...`.
 * Master keys themselves should never live in a browser tab; mint
 * the agent cert + key elsewhere and pass them in.
 */
export interface CertAuthConfig {
  type: "cert";
  /** Encoded api.Cert protobuf bytes (the file mosey cert mint-agent writes). */
  cert: Uint8Array;
  /** 64-byte Ed25519 private key (Go's seed || public form). */
  privateKey: Uint8Array;
  /** 32-byte Ed25519 public key the verifier authenticates the server's cert against. */
  masterPub: Uint8Array;
  /** Workspace identifier the peer cert must declare. */
  workspaceId: string;
  /** Optional initial set of revoked cert serials. Live-updatable via updateRevoked(). */
  revoked?: ReadonlySet<string>;
}

export type AuthConfig = PSKAuthConfig | CertAuthConfig;

export interface ConnectOptions {
  /** WebSocket base URL — `ws://host:port` or `wss://host:port`. */
  endpoint: string;
  auth: AuthConfig;
}

/**
 * MoseyClient is one attach session. Construction = auth +
 * PTY-stream open; the PTY stream is exposed via onData / write
 * and the optional control stream via resize.
 */
export class MoseyClient {
  private peerToken: string;
  private endpoint: string;
  private ptyStream: Stream;
  private controlStream?: Stream;

  // certAuth is held only when auth.type === "cert" so updateRevoked
  // has somewhere to write. Today's MoseyClient doesn't reconnect, so
  // updates only affect future reconnect/resume work — but the API
  // shape matches the Go side's CertAuth.UpdateRevoked.
  private certAuth?: CertAuthConfig;

  /**
   * connect opens an authenticated attach session against
   * `opts.endpoint`. Throws on auth failure or PTY-open failure.
   * For cert auth, validates the local cert + key pair fail-fast
   * before opening the auth stream — matches NewCertAuth on the
   * Go side.
   */
  static async connect(opts: ConnectOptions): Promise<MoseyClient> {
    if (opts.auth.type === "cert") {
      await validateCertConfig(opts.auth);
    }

    const peerToken = mintPeerToken();

    // 1. Auth handshake on /mosey/auth/.
    const authStream = await Stream.open({
      endpoint: opts.endpoint,
      proto: ProtoAuth,
      peerToken,
    });
    try {
      await runAuth(authStream, opts.auth);
    } catch (err) {
      authStream.close();
      throw err;
    }

    // 2. Open the PTY application stream. Auth-wrap on the server
    //    correlates this with the just-completed handshake via the
    //    shared peerToken.
    let ptyStream: Stream;
    try {
      ptyStream = await Stream.open({
        endpoint: opts.endpoint,
        proto: ProtoPTY,
        peerToken,
      });
    } catch (err) {
      throw new Error(
        `mosey/client: PTY stream open failed: ${(err as Error).message}`,
      );
    }

    const c = new MoseyClient(opts.endpoint, peerToken, ptyStream);
    if (opts.auth.type === "cert") {
      c.certAuth = opts.auth;
    }
    return c;
  }

  private constructor(endpoint: string, peerToken: string, pty: Stream) {
    this.endpoint = endpoint;
    this.peerToken = peerToken;
    this.ptyStream = pty;
  }

  /**
   * updateRevoked swaps in a new revoked-serial set for any future
   * reconnect / resume that re-runs the cert handshake. Throws when
   * the client was authenticated with PSK — there is no revocation
   * concept on that path.
   */
  updateRevoked(revoked: ReadonlySet<string>): void {
    if (!this.certAuth) {
      throw new Error(
        "mosey/client: updateRevoked only meaningful with cert auth",
      );
    }
    this.certAuth = { ...this.certAuth, revoked };
  }

  /**
   * onData subscribes to PTY output bytes. Each callback invocation
   * delivers one WebSocket binary frame's worth (whatever the
   * server flushed). Replaces any prior handler.
   *
   * Wire to a terminal emulator like xterm.js:
   *   const decoder = new TextDecoder();
   *   client.onData(b => term.write(decoder.decode(b)));
   */
  onData(handler: (data: Uint8Array) => void): void {
    this.ptyStream.onData(handler);
  }

  /** write sends keystroke bytes to the remote PTY. */
  write(data: Uint8Array): void {
    this.ptyStream.send(data);
  }

  /**
   * resize forwards a new terminal size to the remote via the
   * control protocol. Opens the control stream lazily on first
   * call. The remote applies min(cols, rows) across all writers
   * to its PTY via TIOCSWINSZ.
   *
   * Treat failures as soft: the control protocol degrades silently
   * (older vterms may not advertise it). We log to console rather
   * than throw so a missing control handler doesn't kill the
   * session.
   */
  async resize(cols: number, rows: number): Promise<void> {
    if (!this.controlStream) {
      try {
        this.controlStream = await Stream.open({
          endpoint: this.endpoint,
          proto: ProtoControl,
          peerToken: this.peerToken,
        });
      } catch (err) {
        console.warn(
          `mosey/client: control stream open failed; resize requests will be dropped: ${(err as Error).message}`,
        );
        return;
      }
    }
    try {
      this.controlStream.sendFramed(encodeControlResize({ cols, rows }));
    } catch (err) {
      console.warn(
        `mosey/client: resize send failed: ${(err as Error).message}`,
      );
    }
  }

  /** close tears down PTY + control streams. Idempotent. */
  async close(): Promise<void> {
    this.ptyStream.close();
    this.controlStream?.close();
  }
}

async function runAuth(stream: Stream, cfg: AuthConfig): Promise<void> {
  switch (cfg.type) {
    case "psk":
      await runPSKHandshake(stream, cfg as PSKAuthOptions);
      return;
    case "cert": {
      const cert = decodeCert(cfg.cert);
      const handshakeOpts: Parameters<typeof runCertHandshake>[1] = {
        masterPub: cfg.masterPub,
        workspaceId: cfg.workspaceId,
        localCert: cert,
        localPriv: cfg.privateKey,
      };
      if (cfg.revoked) handshakeOpts.revoked = cfg.revoked;
      await runCertHandshake(stream, handshakeOpts);
      return;
    }
  }
}

/**
 * validateCertConfig fails fast on configuration mistakes BEFORE
 * opening the auth stream:
 *   - private key is 64 bytes (Go's seed || public form)
 *   - master pub is 32 bytes
 *   - workspaceId is non-empty
 *   - the local cert verifies against this masterPub + workspaceId
 *     (catches mismatched master / cert files, expired certs,
 *     wrong workspace) — mirrors NewCertAuth in auth/cert.go
 *   - the cert's peer_pubkey matches the public half of privateKey
 *     (catches mismatched cert / key pairs) — also mirrors NewCertAuth
 */
async function validateCertConfig(cfg: CertAuthConfig): Promise<void> {
  if (cfg.privateKey.length !== ED25519_PRIVATE_KEY_SIZE) {
    throw new Error(
      `mosey/client: privateKey length ${cfg.privateKey.length}, want ${ED25519_PRIVATE_KEY_SIZE}`,
    );
  }
  if (cfg.masterPub.length !== ED25519_PUBLIC_KEY_SIZE) {
    throw new Error(
      `mosey/client: masterPub length ${cfg.masterPub.length}, want ${ED25519_PUBLIC_KEY_SIZE}`,
    );
  }
  if (cfg.workspaceId === "") {
    throw new Error("mosey/client: workspaceId is required for cert auth");
  }

  let cert: Cert;
  try {
    cert = decodeCert(cfg.cert);
  } catch (err) {
    throw new Error(
      `mosey/client: decode local cert: ${(err as Error).message}`,
    );
  }

  const verifyOpts: Parameters<typeof verifyCert>[1] = {
    masterPub: cfg.masterPub,
    workspaceId: cfg.workspaceId,
  };
  if (cfg.revoked) verifyOpts.revoked = cfg.revoked;
  const claim = await verifyCert(cert, verifyOpts);

  // The public half of a Go-style 64-byte Ed25519 key sits in bytes
  // 32..64. Comparing against the cert's declared peer_pubkey
  // catches the "I swapped two key files" mistake before a confusing
  // handshake failure.
  const declaredPub = claim.peerPubkey;
  const actualPub = cfg.privateKey.subarray(32, 64);
  if (!bytesEqual(declaredPub, actualPub)) {
    throw new Error(
      "mosey/client: privateKey public half does not match localCert.peer_pubkey",
    );
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
