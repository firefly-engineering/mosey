# Wire model and protocols

mosey runs three application-level protocols on top of an
authenticated stream transport. Every protocol has a string ID that
follows libp2p convention:

| Protocol ID | Direction | Purpose |
|---|---|---|
| `/mosey/auth/1.0.0` | client → server (then bidi) | Handshake. Three messages prove both peers hold the credential. |
| `/mosey/pty/1.0.0` | bidi | The PTY byte stream itself. |
| `/mosey/pty-resume/1.0.0` | bidi | Reattach with replay. First message is a varint `last_seq`. |
| `/mosey/control/1.0.0` | bidi | Length-delimited typed messages: Resize, Signal, SetMode, Promote, Kick, Demote, ListClients. |

The protocol IDs — and the HKDF context labels (`mosey-cert-v1`,
`mosey-cert-master`) used in cert + master-key derivation — are
load-bearing for the wire format and for every workspace master
ever generated. Bumping the trailing version number is the
sanctioned way to change them; the constants live in
`internal/api/protocols.go` and `internal/cert/master.go`.

## Protocol lifecycle

```
                       ┌──── client ────┐                ┌──── server ────┐
                       │                │                │                │
   Dial(target)  ──────┼──> /mosey/auth/ │                │                │
                       │     HMAC-SHA256 challenge / response (3 msgs)    │
                       │                ├────────────────┤  Identity +    │
                       │                │                │  Capabilities  │
                       │                │                │  stored        │
                       │   ackOK byte   ├────────────────┤                │
                       │                │                │                │
   Dial(target, PROTO) ─┼──> /mosey/pty/ ─┼──> handler sees authed Stream  │
                       │  application bytes flow ↔                       │
                       └────────────────┘                └────────────────┘
```

The `ackOK` byte is the synchronization gate. Without it the client
could race ahead and open `/mosey/pty/` before the server has
finished writing the [`Identity`] into its session table; the
handler would then run with an empty capability set. See
`internal/auth/wrap.go` for the gory details.

[`Identity`]: ../../internal/auth/identity.go

## The auth wrap

`auth.Wrap(transport, authenticator)` returns a `Transport` that
behaves identically to the inner one except:

1. `Serve()` registers `/mosey/auth/` on the inner transport.
2. `Dial(target, PROTO)` always runs the handshake before opening
   `PROTO`.
3. Inbound streams on `PROTO != /mosey/auth/` are silently closed
   unless a prior handshake from the same remote completed
   successfully.

This lets every other layer treat the post-auth `Stream` as if it
were already trusted. The Authenticator interface accepts either a
PSK or a workspace cert — see [auth](auth.md).

## PTY fan-out

The vterm session owns one `os/exec` child and one PTY master. The
child's output is **never streamed directly** to attached clients —
it's funneled through an `OutputRing` (in
`internal/streambuf/`) and from there fanned out to each attached
client's outbound buffer.

That indirection buys two properties:

- **Replay.** Each byte the ring stores is tagged with a sequence
  number. When a client reattaches via `/mosey/pty-resume/`, it
  sends the last sequence it rendered locally; the server replays
  from there. The ring is bounded — old data is overwritten — so
  replay is best-effort. See [reattach](reattach.md).
- **Per-client backpressure isolation.** A slow client's buffer
  fills independently. Once it overruns, that one client is
  dropped; the others keep streaming uninterrupted.

Input flows the other direction. Each writer's bytes are
serialized through a single lock before being written to the PTY
master, so writes from concurrent clients interleave at byte
granularity (the kernel still sees one ordered byte stream).
Whether multiple clients _are_ writers is the mode policy's call —
see [multi-client modes](multi-client.md).

## Geometry: the min(cols, rows) rule

Every attached client reports its local terminal size via
`Resize`. The vterm picks `min(cols)` × `min(rows)` across all
writers and applies it to the PTY via `TIOCSWINSZ`. Readers'
geometry is recorded but ignored — they get whatever the writer
group agreed on, padded or letterboxed by their local TUI.

The minimum rule is the only choice that doesn't corrupt at least
one client's render. Picking the maximum would produce bytes past
the smaller client's column count; picking the first writer's size
would tear when they detach. Min loses real estate on a wide
client but never produces nonsense.

## Out-of-band: the control channel

`/mosey/control/` carries length-delimited
[`ControlMessage`](../../internal/api/control.proto) envelopes. v1
messages all flow attach → vterm and are fire-and-forget except
`ListClients`, which replies with `ClientList` on the same stream.

Authorization is per-message. The server checks the sender's
`Capabilities` (stored at handshake time) against the action: only
`Owner` can `SetMode`, `Promote`, `Kick`. Any client can issue
`Demote` (drop your own perms) or `ListClients` (see who else is
here). Messages from clients lacking the cap are silently dropped —
the protocol intentionally returns no error code, since a malicious
client would simply ignore it anyway.

## Why two transports?

mosey carries **libp2p** and **HTTP/2** backends behind one
`transport.Transport` interface, aggregated by `transport.Multi`.

- **libp2p** is the production cross-host transport — handles
  Noise-encrypted handshakes, multi-protocol negotiation, DCUtR
  hole-punching, and TCP + QUIC simultaneously. It's the only
  backend you'd expose to the open internet.
- **HTTP/2** (with cleartext h2c or HTTPS) is the corporate-
  proxy / browser-bridge transport. It tunnels the same Stream
  semantics through an HTTP framework so existing TLS infra
  (reverse proxies, certificate stores, load balancers) can carry
  mosey traffic. It cannot punch holes — both peers need IP
  reachability.

A single `launch` can listen on both by repeating `--listen`. The
authenticator and session layers don't care which backend a stream
came in on. See [transports](transports.md).
