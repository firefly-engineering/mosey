# `@firefly-engineering/mosey-client`

Reference TypeScript / browser client for [mosey](../../) — speaks
the WebSocket transport, drives the PSK auth handshake, and
exposes the PTY byte stream as a callback-friendly API.

Zero runtime dependencies: uses the platform `WebSocket`,
`crypto.subtle`, and `TextEncoder`/`TextDecoder`. The cert auth
path additionally relies on `crypto.subtle`'s `Ed25519` algorithm,
which lands in Chrome 113+, Firefox 130+, Safari 17+, and Node
18.4+. Works in any modern browser and in Node 22+ (where
`WebSocket` became a global).

## Status

Pre-v0.1. PSK auth + the PTY byte stream + the Resize control
message work end-to-end against a live `mosey launch` (see the
e2e test). Cert auth, the rest of the control protocol, and a
companion `xterm.js` integration package are on the roadmap.

## Install

```sh
npm install @firefly-engineering/mosey-client
```

(Not yet published; clone the repo and `npm pack` from
`clients/typescript/` for now.)

## Quickstart

```ts
import { MoseyClient } from "@firefly-engineering/mosey-client";

const client = await MoseyClient.connect({
  endpoint: "wss://host:8443",
  auth: { type: "psk", secret: "hunter2" },
});

const decoder = new TextDecoder();
client.onData((bytes) => {
  // bytes is a Uint8Array; one binary frame per callback.
  process.stdout.write(decoder.decode(bytes));
});

process.stdin.on("data", (buf) => client.write(buf));

// Forward a window resize:
client.resize(120, 40);

// On exit:
await client.close();
```

## With xterm.js

The wire surface is `Uint8Array` in / `Uint8Array` out. Bridging
to `xterm.js`:

```ts
import { Terminal } from "@xterm/xterm";
import { MoseyClient } from "@firefly-engineering/mosey-client";

const term = new Terminal();
term.open(document.getElementById("terminal")!);

const client = await MoseyClient.connect({
  endpoint: "wss://localhost:8443",
  auth: { type: "psk", secret: "hunter2" },
});

const decoder = new TextDecoder();
const encoder = new TextEncoder();

client.onData((bytes) => term.write(decoder.decode(bytes)));
term.onData((str) => client.write(encoder.encode(str)));
term.onResize(({ cols, rows }) => void client.resize(cols, rows));

window.addEventListener("beforeunload", () => void client.close());
```

A standalone HTML demo lives in
[`examples/xterm-demo.html`](examples/xterm-demo.html).

## API

### `MoseyClient.connect(opts) → Promise<MoseyClient>`

| Option | Type | Notes |
|---|---|---|
| `endpoint` | `string` | `ws://host:port` or `wss://host:port`. Path is ignored — the client appends `/mosey/<proto>/1.0.0`. |
| `auth` | `{ type: "psk"; secret: string; label?: string }` | Plaintext shared secret matching the launcher's `--secret`. The optional `label` lets you target a non-owner role (e.g. `"reader"`). |

Returns a connected `MoseyClient`. Throws on auth failure or
transport failure.

### `client.onData(handler)`

Subscribes to PTY output bytes. The handler receives one
`Uint8Array` per binary frame. Replaces any prior subscription —
single subscriber by design.

### `client.write(bytes: Uint8Array)`

Sends keystroke bytes to the remote PTY.

### `client.resize(cols, rows) → Promise<void>`

Forwards a terminal-size change via the control protocol. Opens
the control stream lazily on first call. Logs to `console.warn`
on failure (e.g. older server without control support) rather
than throwing — keeps the session alive.

### `client.close() → Promise<void>`

Tears down PTY + control streams. Idempotent.

## Lower-level building blocks

For custom transports or extending the protocol surface, the
package also exports:

- `Stream` — async WebSocket wrapper with protodelim framing.
- `runPSKHandshake(stream, opts)` — just the auth flow.
- `derivePSKKey`, `hmacSHA256`, `randomNonce`,
  `constantTimeEqual` — WebCrypto helpers matching `psk.go`'s
  derivation and MAC labels.
- `encodeAuthClientHello`, `decodeAuthMessage`,
  `encodeControlResize` — hand-rolled protobuf encoders /
  decoders for the wire messages.
- `mintPeerToken`, `PEER_TOKEN_PREFIX`, `ProtoAuth`, `ProtoPTY`,
  `ProtoControl` — the constants the transport agrees on.

## Why no protobuf library?

Three messages on the wire, all small. Hand-coding gives:

- Zero runtime dependencies.
- A single 200-line file (`src/proto.ts`) you can audit in one
  sitting.
- No codegen step in the install path.

If the surface grows (more control messages, cert auth payloads)
swap in [`protobuf-ts`](https://github.com/timostamm/protobuf-ts)
or [`ts-proto`](https://github.com/stephenh/ts-proto). The
proto.ts encoders are deliberately self-contained so the swap
is localized.

## Development

```sh
npm install            # one-time
npm test               # vitest unit + e2e
npm run typecheck      # tsc --noEmit
npm run build          # tsc → dist/
```

The e2e test under `test/e2e.test.ts` requires
`../../bin/mosey` to exist (build the Go binary with
`just build` from the repo root). It auto-skips otherwise.

## Spec reference

The wire format this client implements lives in:

- [`docs/src/design.md`](../../docs/src/design.md) — wire model
  + protocol IDs.
- [`docs/src/auth.md`](../../docs/src/auth.md) — PSK + cert auth.
- [`docs/src/transports.md`](../../docs/src/transports.md) —
  WebSocket-specific details (peer-token correlation,
  subprotocol use, half-close limitations).
