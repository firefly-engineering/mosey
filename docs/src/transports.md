# Transports

The `transport.Transport` interface is the only surface higher
layers depend on. Three backends are included today; new ones plug
in by implementing the same shape.

```go
type Transport interface {
    Schemes() []string
    Endpoints() []string
    Handle(proto string, h Handler)
    Unhandle(proto string)
    Dial(ctx, target, proto) (Stream, error)
    Serve()
    Close() error
}
```

`transport.Multi(a, b, ...)` aggregates several backends behind one
`Transport`. Inbound handlers are mirrored to all backends; outbound
dials route by URI scheme. A single `launch` listening on both
libp2p and HTTPS uses one `Multi` wrapping both backends.

## libp2p backend

The production cross-host transport.
[`internal/transport/libp2p`](../../internal/transport/libp2p/)
wraps go-libp2p with:

- **Noise** for confidentiality and authentication of the
  underlying libp2p channel. (mosey adds its own `/mosey/auth/` layer
  on top — Noise authenticates _peers_ at the transport layer;
  mosey authenticates _workspaces_ at the application layer.)
- **TCP + QUIC** listeners by default. QUIC carries the bulk of
  cross-NAT traffic; TCP is the fallback path and what existing
  proxies / port-forwards usually understand.
- **DCUtR (Direct Connection Upgrade through Relay)** hole-punching
  so two peers behind asymmetric NATs can usually upgrade from
  a relayed initial contact to a direct connection.
- **IPFS public bootstrap peers** as the default relay set, so a
  fresh process finds at least one rendezvous point without
  config. `--no-p2p-bootstrap` disables this (LAN-only / offline).

The endpoint is a libp2p multiaddr ending in `/p2p/<peer-id>`.
mosey doesn't have its own discovery — the calling project has to
carry the multiaddr from launcher to attacher somehow (Slack, env
var, a dedicated registry).

## HTTP/2 backend

[`internal/transport/http2`](../../internal/transport/http2/) ports
the same `Stream` semantics onto HTTP/2 framing.

```
POST /<proto> HTTP/2
  → request body streams Stream.Write(client→server)
  → response body streams Stream.Read(server→client)
```

The protocol ID rides in the URL path. Half-close maps to
HTTP/2's end-stream flag — `Stream.CloseWrite()` finishes the
request body without closing the response stream, just like
`/mosey/auth/` requires.

Two flavours of listener:

- `http://host:port` — cleartext h2c (RFC 7540 §3.4). Useful for
  intra-cluster setups behind a TLS-terminating sidecar, and for
  the integration tests.
- `https://host:port` — TLS with `--http-cert` / `--http-key`. The
  client side gets `--insecure-tls` for self-signed dev certs.

The HTTP/2 backend is **dial-only** when constructed without a
`ListenAddr` — that's how `mosey attach` and `mosey control`
configure it: they're never servers, so there's no listening port
to bind.

## Unix domain socket backend

[`internal/transport/unix`](../../internal/transport/unix/) speaks
the `unix://` scheme. Same-host attaches only — no network port,
no TLS, no libp2p bootstrap.

```sh
mosey launch --secret=hunter2 --listen=unix:///tmp/mosey.sock -- bash
mosey attach --secret=hunter2 unix:///tmp/mosey.sock
```

Wire model: one socket per stream. On `Dial` the client opens a
fresh `net.UnixConn`, writes a varint-length-prefixed protocol id,
and the rest of the socket is the bidi byte stream. The server
reads the prefix on accept and dispatches to the matching handler.
No multiplexer — unix sockets are cheap enough that per-stream
connections are a non-issue.

Identity correlation across the auth → application stream sequence
falls out of **peer credentials** rather than connection address.
Each `accept(2)` on the server side pulls (uid, pid) via
`SO_PEERCRED` (Linux) or `LOCAL_PEERCRED` + `LOCAL_PEERPID`
(macOS) and surfaces them as `Stream.RemoteID()` like
`"unix:uid=1000:pid=12345"`. The same caller process produces the
same RemoteID across both streams, so `auth.Wrap` correlates them
the same way it does with a libp2p peer id or an HTTP `RemoteAddr`.

Limitations:

- POSIX only (Linux + macOS today; Windows would need a different
  peer-cred surface).
- The listener path must fit the OS's `sun_path` cap — about 104
  bytes on macOS, 108 on Linux. Use short paths under `/tmp/` or
  `$XDG_RUNTIME_DIR`.
- Stale socket files from a crashed launcher are removed on
  `New()`; co-located launchers on the same path will race.

## When to use which

| Constraint | Backend |
|---|---|
| Same-host attach (one daemon + local attacher) | unix (`--listen=unix:///path`) |
| Two LAN hosts, no config | libp2p (`mosey launch` with no `--listen` picks libp2p:// by default) |
| Two hosts on different networks, NAT each side | libp2p (relies on DCUtR) |
| Browser bridge, or behind a corporate HTTPS-only proxy | http2 (`--listen=https://...`) |
| Want both at once | both — repeat `--listen` |
| Air-gapped LAN | libp2p with `--no-p2p-bootstrap` |
| Want existing TLS infra (cert pinning, mTLS, ALB) | http2 |
| Want to skip the network entirely for embedded use | unix |

## Implementing a new backend

The contract is small:

1. Implement `Transport` and its `Stream` half-close + `RemoteID`.
2. Return a unique scheme from `Schemes()` so `Multi`'s router can
   reach you.
3. Tolerate concurrent handler registration, dials, and `Close()`.
4. Honor `ctx.Done()` in `Dial` and in the `Serve()` accept loop.

The integration tests under `internal/transport/http2/` are a good
template — they exercise the auth + PTY + control paths end-to-end
against a real local listener.
