# Transports

The `transport.Transport` interface is the only surface higher
layers depend on. Two backends ship today; new ones plug in by
implementing the same shape.

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
  underlying libp2p channel. (mosey adds its own `/ship/auth/` layer
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
ship the multiaddr from launcher to attacher somehow (Slack, env
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
`/ship/auth/` requires.

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

## When to use which

| Constraint | Backend |
|---|---|
| Two LAN hosts, no config | libp2p (`mosey launch` with no `--listen` picks libp2p:// by default) |
| Two hosts on different networks, NAT each side | libp2p (relies on DCUtR) |
| Browser bridge, or behind a corporate HTTPS-only proxy | http2 (`--listen=https://...`) |
| Want both at once | both — repeat `--listen` |
| Air-gapped LAN | libp2p with `--no-p2p-bootstrap` |
| Want existing TLS infra (cert pinning, mTLS, ALB) | http2 |

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
