// MoseyClient — the high-level surface most callers want. Wraps:
//
//   1. PSK auth handshake on /mosey/auth/1.0.0
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
//
// Today only PSK auth is implemented. Cert auth lives on the
// roadmap; master keys belong on operator laptops, not in browser
// tabs, so the browser-friendly subset is "PSK".

import { PSKAuthOptions, runPSKHandshake } from "./auth.js";
import { encodeControlResize } from "./proto.js";
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

export type AuthConfig = PSKAuthConfig;

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

  /**
   * connect opens an authenticated attach session against
   * `opts.endpoint`. Throws on auth failure or PTY-open failure.
   */
  static async connect(opts: ConnectOptions): Promise<MoseyClient> {
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

    return new MoseyClient(opts.endpoint, peerToken, ptyStream);
  }

  private constructor(endpoint: string, peerToken: string, pty: Stream) {
    this.endpoint = endpoint;
    this.peerToken = peerToken;
    this.ptyStream = pty;
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
      return runPSKHandshake(stream, cfg as PSKAuthOptions);
  }
}
