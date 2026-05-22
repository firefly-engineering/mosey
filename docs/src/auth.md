# Authentication

mosey has two authenticators that share an interface. Pick one per
deployment — they're mutually exclusive at the flag layer.

## Authenticator interface

```go
type Authenticator interface {
    ServerHandshake(stream io.ReadWriter) (*Identity, error)
    ClientHandshake(stream io.ReadWriter) error
}
```

Both flavours produce an `Identity` carrying a label (`"owner"`,
`"reader"`, or a cert subject) and a `Capabilities` set with three
bits: `Owner`, `Write`, `Resize`. Every higher layer authorizes
against those bits — there is no other policy surface.

## PSK authentication

```sh
mosey launch --secret=hunter2 -- bash
mosey attach --secret=hunter2 ENDPOINT
```

Both peers prove possession of `hunter2` via a three-message
HMAC-SHA256 challenge / response. No certificate, no PKI. Caps come
from the flag: anyone presenting `--secret` gets `Owner | Write |
Resize`; anyone presenting the optional `--reader-secret` gets the
empty cap set (observer-only).

PSK is the right choice for:

- Single-user, multi-device setups (laptop + desktop sharing a
  workspace via a secret in `pass`).
- Quick demos and pair-programming.
- LAN-bounded usage where the secret travels alongside the
  multiaddr in something already trusted (Slack DM, password
  manager).

PSK is the wrong choice when membership rotates often (you'd have
to redeploy the secret everywhere), or when audit logs need to
attribute actions to individuals.

## Cert authentication

The cert flow lets one **workspace master** sign per-agent certs
that mosey verifies on connect.

```sh
mosey cert mint-master --out=./ws
# Prints a BIP-39 mnemonic. Record it.
# Files: ./ws/master.key  ./ws/master.pub

mosey cert mint-agent \
    --master-key=./ws/master.key \
    --workspace=demo \
    --agent-id=alice \
    --label=alice \
    --caps=owner,write,resize \
    --valid-for=720h \
    --out=./ws
# Files: ./ws/alice.cert  ./ws/alice.key
```

Both sides then dial / listen with the cert flags:

```sh
mosey launch \
    --cert=./ws/alice.cert --key=./ws/alice.key \
    --master-pub=./ws/master.pub --workspace=demo \
    -- bash
```

### What lives in a cert?

The wire form is a protobuf (`api/cert.proto`) carrying:

- The agent's Ed25519 public key (so the cert binds to its
  keypair — possessing the cert without the key is useless).
- A capability bitmask (`owner`, `write`, `resize`).
- A workspace ID (so the same agent can hold separate certs for
  separate workspaces).
- A ULID serial (revocation target).
- `NotBefore` / `NotAfter` validity window.

The cert is signed by the master's Ed25519 key. Verification: every
mosey peer carries the master's public key (`master.pub`) and the
workspace ID; on handshake it checks the signature, the workspace
ID match, the validity window, and the revocation list.

### Master key handling

The master key is the workspace's root of trust. **Never put it on
a server.** Mint it on a laptop, write the mnemonic to a password
manager + paper backup, and use it only when minting or revoking.
A compromised master means re-minting every cert and rotating
`master.pub`.

The mnemonic is BIP-39 — 24 words, recoverable via HKDF-SHA256 with
the `mosey-cert-master` context label. The HKDF labels are baked
into verification, so changing them invalidates every existing key.

### Revocation

`mosey cert revoke --revocation-file=PATH --serial=SERIAL` appends
a serial to a file. The running `launch` process re-reads its
`--revocation-file` on SIGHUP and refuses handshakes from any cert
whose serial appears in the list.

Reasons to revoke: laptop lost, contractor offboarded, key
suspected leaked. Reasons not to revoke: cert expired (handle via
`NotAfter`), cap downgrade (mint a new cert).

The revocation file is plain text: one serial per line, comments
beginning with `#`. Parsing is liberal — a malformed file logs a
warning and keeps the previous list rather than failing closed,
because the operator pressing SIGHUP after a typo shouldn't lock
themselves out.

## Capability semantics

Three bits, evaluated independently:

| Bit | Grants |
|---|---|
| `Owner` | Issue `SetMode`, `Promote`, `Kick` on the control channel. |
| `Write` | Send keystrokes to the PTY. |
| `Resize` | Send `Resize` to change the remote PTY size. |

Caps come from the credential (PSK `--secret` vs.
`--reader-secret`, or the cert's `caps` bitmask) and are subject to
runtime tightening by the [multi-client mode](multi-client.md) (a
`PrimaryObserver` reader can hold `Write` in their cert but be
denied at the session layer until promoted). The cap set never
widens at runtime — `mosey control promote` flips a session-layer
flag, not the cap bits.

## Identity semantics across backends

`auth.Wrap` produces the same `Identity` shape on every backend.
Handlers retrieve it with `auth.IdentityOf(stream)`, which returns
the post-handshake `Identity` — the `Label` and `Caps` derived from
whichever credential (PSK secret or cert) the client presented. The
auth wrapper is responsible for that uniformity: each backend
contributes only a *correlation key* (the value of
`Stream.RemoteID()`) that lets the wrapper match the auth stream
and the application stream from the same peer.

| Backend | Correlation key (`Stream.RemoteID()`) |
|---|---|
| `libp2p` | The remote libp2p peer ID (multihash). Stable across the lifetime of the libp2p Host. |
| `http2` | The remote TCP `host:port` of the dialer's HTTP/2 connection. Every stream the same client multiplexes over that connection arrives with the same `RemoteID`. |
| `websocket` | `ws-peer:<token>` — a per-process random token the dialing Backend offers in `Sec-WebSocket-Protocol` on every outbound socket, so each per-stream WebSocket from the same dialer correlates server-side. |
| `unix` | `unix:uid=<uid>:pid=<pid>` from peer credentials (`LOCAL_PEERCRED`/`LOCAL_PEERPID` on darwin, `SO_PEERCRED` on linux). Server reads peer creds lazily — a dialer that closes a stream before the handler runs may have its peer-creds read fail and the stream silently rejected. |

In every case `IdentityOf` returns the same `Identity` shape — the
backend choice doesn't leak into the auth surface. Streams that
arrive without a prior successful handshake on the same correlation
key are silently dropped by the wrapper; the application handler
never sees them.

The cross-backend contract is pinned by `TestIdentityOf_AcrossBackends`
in `auth/identity_backends_test.go` — it runs an owner + reader
dial through each backend and asserts the captured `Identity`
matches the credential. Add the new backend to that test before
shipping it.
