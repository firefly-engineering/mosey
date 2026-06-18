// WebSocket wrapper that exposes the same Stream-ish surface the
// rest of the client code expects: send arbitrary bytes, receive
// arbitrary bytes (or framed protodelim messages), close cleanly.
//
// The mosey wire model is one WebSocket per stream with the
// protocol id in the URL path. The dialer offers a stable
// per-process token via Sec-WebSocket-Protocol so the server can
// correlate the auth + application streams as one identity (see
// internal/transport/websocket/websocket.go).

import { readProtodelim, withProtodelim } from "./proto.js";

export const PEER_TOKEN_PREFIX = "mosey-peer-";

/** Protocol IDs mosey serves; kept here so callers don't repeat the path strings. */
export const ProtoAuth = "/mosey/auth/1.0.0";
export const ProtoPTY = "/mosey/pty/1.0.0";
export const ProtoControl = "/mosey/control/1.0.0";

export interface OpenOptions {
  /**
   * Full WebSocket URL base — `wss://host:port` or `ws://host:port`.
   * Protocol id is appended to form the dialed URL. The path on
   * `endpoint` is ignored.
   */
  endpoint: string;
  /** mosey protocol id, e.g. ProtoAuth. */
  proto: string;
  /**
   * Per-process peer token. Same string on every stream from one
   * client process so the server uses it as a stable RemoteID for
   * auth correlation. Pass the value from `mintPeerToken()`.
   */
  peerToken: string;
}

/**
 * Stream is a thin async wrapper around a binary WebSocket. The
 * mosey protocols ride as binary frames; this type handles the
 * frame ↔ byte adaptation so callers can think in protodelim
 * messages and raw byte streams.
 *
 * One concurrent reader + one concurrent writer is supported
 * (mirrors the constraint the Go gorilla/websocket library
 * imposes on the server side). Multiple concurrent readers are
 * not — there's no internal queue, so a second `readMessage` call
 * before the first resolves will steal the next frame.
 */
export class Stream {
  private ws: WebSocket;
  private buffer = new Uint8Array(0);
  private pendingResolvers: Array<{
    resolve: (value: Uint8Array) => void;
    reject: (err: Error) => void;
  }> = [];
  private closed = false;
  private closeError?: Error;

  static async open(opts: OpenOptions): Promise<Stream> {
    const url = buildURL(opts.endpoint, opts.proto);
    const subprotocol = PEER_TOKEN_PREFIX + opts.peerToken;
    const ws = new WebSocket(url, [subprotocol]);
    ws.binaryType = "arraybuffer";
    await waitForOpen(ws);
    return new Stream(ws);
  }

  private constructor(ws: WebSocket) {
    this.ws = ws;
    ws.onmessage = (ev) => this.onMessage(ev);
    ws.onerror = () => this.fail(new Error("mosey/transport: websocket error"));
    ws.onclose = (ev) => {
      // Codes 1000 (normal) / 1001 (going away) / 1005 (no status)
      // are clean EOF. Anything else surfaces as an error.
      if (ev.code === 1000 || ev.code === 1001 || ev.code === 1005) {
        this.fail(new Error("mosey/transport: stream closed"));
      } else {
        this.fail(new Error(`mosey/transport: websocket closed (${ev.code}): ${ev.reason}`));
      }
    };
  }

  /** Send raw bytes as one binary frame. */
  send(data: Uint8Array): void {
    if (this.closed) throw this.closeError ?? new Error("mosey/transport: stream closed");
    this.ws.send(data);
  }

  /**
   * Send one protodelim-framed message: prepend a varint length to
   * `body` and emit as one binary frame. Mirrors how the Go side
   * writes auth / control messages.
   */
  sendFramed(body: Uint8Array): void {
    this.send(withProtodelim(body));
  }

  /**
   * Read the next protodelim-framed message off the wire. Resolves
   * with the message body (no length prefix). Rejects if the
   * stream closes before a full frame arrives.
   */
  async readFramed(): Promise<Uint8Array> {
    // Try to satisfy from buffered bytes first.
    const ready = readProtodelim(this.buffer);
    if (ready) {
      this.buffer = this.buffer.slice(ready.n);
      return ready.msg;
    }
    if (this.closed) throw this.closeError ?? new Error("mosey/transport: stream closed");
    return new Promise((resolve, reject) => {
      this.pendingResolvers.push({ resolve, reject });
    });
  }

  /**
   * Subscribe to raw incoming bytes — every binary frame is
   * delivered as one Uint8Array. Use after the auth handshake on
   * the PTY stream to feed terminal output to a renderer.
   *
   * Replaces any prior handler (single subscriber by design).
   */
  onData(handler: (data: Uint8Array) => void): void {
    this.dataHandler = handler;
    this.dataMode = true;
    // Flush anything already buffered.
    if (this.buffer.length > 0) {
      handler(this.buffer);
      this.buffer = new Uint8Array(0);
    }
  }

  /** Close the underlying WebSocket. Idempotent. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.ws.close(1000);
    } catch {
      // ignore — close is best-effort
    }
  }

  private dataHandler?: (data: Uint8Array) => void;
  private dataMode = false;

  private onMessage(ev: MessageEvent): void {
    if (!(ev.data instanceof ArrayBuffer)) return; // ignore text / pings
    const chunk = new Uint8Array(ev.data);

    if (this.dataMode && this.dataHandler) {
      this.dataHandler(chunk);
      return;
    }

    // Append to buffer; try to resolve a pending readFramed.
    if (this.buffer.length === 0) {
      this.buffer = chunk;
    } else {
      const merged = new Uint8Array(this.buffer.length + chunk.length);
      merged.set(this.buffer, 0);
      merged.set(chunk, this.buffer.length);
      this.buffer = merged;
    }
    while (this.pendingResolvers.length > 0) {
      const ready = readProtodelim(this.buffer);
      if (!ready) break;
      this.buffer = this.buffer.slice(ready.n);
      const waiter = this.pendingResolvers.shift()!;
      waiter.resolve(ready.msg);
    }
  }

  private closeWaiters: Array<(err: Error) => void> = [];

  /**
   * whenClosed resolves with the close error when the peer closes or
   * the socket errors. Lets a raw-byte reader (e.g. the auth ack)
   * notice a server that drops the stream instead of replying —
   * readFramed already rejects on close via pendingResolvers, but a
   * one-off byte read has no frame to wait on.
   */
  whenClosed(): Promise<Error> {
    if (this.closed) {
      return Promise.resolve(this.closeError ?? new Error("mosey/transport: stream closed"));
    }
    return new Promise((resolve) => {
      this.closeWaiters.push(resolve);
    });
  }

  private fail(err: Error): void {
    this.closed = true;
    this.closeError = err;
    for (const w of this.pendingResolvers) w.reject(err);
    this.pendingResolvers = [];
    for (const w of this.closeWaiters) w(err);
    this.closeWaiters = [];
  }
}

function buildURL(endpoint: string, proto: string): string {
  const u = new URL(endpoint);
  if (u.protocol !== "ws:" && u.protocol !== "wss:") {
    throw new Error(`mosey/transport: endpoint must be ws:// or wss://, got ${u.protocol}`);
  }
  u.pathname = proto;
  return u.toString();
}

function waitForOpen(ws: WebSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    if (ws.readyState === WebSocket.OPEN) {
      resolve();
      return;
    }
    ws.onopen = () => resolve();
    ws.onerror = () => reject(new Error("mosey/transport: websocket open failed"));
  });
}

/**
 * mintPeerToken returns 32 hex chars of crypto-random data. Use
 * once per client construction and reuse on every Stream.open so
 * the server correlates auth + application streams via the
 * Sec-WebSocket-Protocol header.
 */
export function mintPeerToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
