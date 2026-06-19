# Browser web-attach (proposal)

> **Status: design proposal.** Nothing here is implemented yet. This
> document designs a [ttyd](https://github.com/tsl0922/ttyd)-equivalent:
> attach to a running `mosey launch` from a web browser, with the
> browser wallet handling authentication when the session was launched
> with [wallet support](wallet-auth.md). It builds entirely on pieces
> that already exist — the [WebSocket transport](transports.md#websocket-backend),
> the [TypeScript client](../../clients/typescript/), the wallet
> handshake, and the inline `signMessage` flow — plus a browser-side
> libp2p transport and (only for strictly-NAT'd hosts) a relay.

## The one idea, and the constraint that bends it

ttyd serves a terminal page that opens a WebSocket back to itself. mosey
already has every browser-facing half of that:
[`MoseyClient`](../../clients/typescript/src/client.ts) speaks the auth +
PTY + control protocols over a WebSocket and pairs with `xterm.js` (see
[`examples/xterm-demo.html`](../../clients/typescript/examples/xterm-demo.html)),
and the wallet path already signs delegations in the browser with
Phantom / Solflare / Backpack.

The naive design is therefore "serve `xterm-demo.html` from the `wss://`
listener and you're done." **That is wrong for the use case**, because of
one constraint:

> The browser may run on a machine that has **no direct network path to
> the mosey host** (the host is behind NAT, the viewer is elsewhere).

A page mosey serves from its own listener presumes the browser can reach
that listener — exactly what the constraint denies. So the web client
must be a **standalone static app** — deployed independently (e.g.
GitHub Pages), running outside any mosey instance — that establishes a
**libp2p connection to the host itself** from inside the browser. The
host's [persisted session keypair *is* its libp2p peer id](wallet-auth.md#session-identity-and-resurrection),
so the only thing a viewer needs is the **session id** (= the peer id)
and, for wallet sessions, their own wallet.

This is not a detour from the wallet-auth design — it is the path that
design was built for. The chain answers *who may attach*; libp2p answers
*where the peer is and how to reach it*; Noise authenticates *that the
peer is the session*; and the wallet handshake authorizes *caps*.

## What already exists (and is reused unchanged)

| Piece | Status | Where |
|---|---|---|
| WebSocket transport (browser-facing) | done | [`transport/websocket/`](../../transport/websocket/) |
| TS client: auth + PTY + control + resize | done | [`clients/typescript/src/client.ts`](../../clients/typescript/src/client.ts) |
| xterm.js wiring | demo | [`examples/xterm-demo.html`](../../clients/typescript/examples/xterm-demo.html) |
| Wallet handshake (server + client) | done | [`auth/wallet.go`](../../auth/wallet.go), [`wallet-auth.ts`](../../clients/typescript/src/wallet-auth.ts) |
| Canonical delegation render/parse (byte-identical Go↔TS) | done | [`wallet/`](../../wallet/), [`wallet-delegation.ts`](../../clients/typescript/src/wallet-delegation.ts) |
| Browser wallet `signMessage` of a delegation | done | the loopback SPA in [`cmd/mosey/wallet.go`](../../cmd/mosey/wallet.go) |

The auth / PTY / control handshakes are **transport-agnostic framed
message exchanges** — they don't care whether the bytes ride a raw
WebSocket or a libp2p stream. That is what makes the libp2p pivot cheap:
only the `Stream` substrate changes.

## Reachability: direct first, relay only as a fallback

How the browser's libp2p node reaches the host depends on one thing:
**does the host have any public reachability?**

### Path A — Direct (preferred, no relay)

If the host can be reached at *some* address a browser can dial, the
browser connects to it **directly** and no relay is involved. A browser
can dial three libp2p transports, any one of which suffices:

| Transport | Host requirement |
|---|---|
| **WebSocket Secure** (`/wss`) | public TCP address + CA-signed TLS cert + domain |
| **WebTransport** (`/webtransport`) | public UDP address + self-signed cert (hash advertised) |
| **WebRTC-Direct** (`/webrtc-direct`) | public UDP address + certhash; no TLS-trust needed |

"Public reachability" is broader than "static public IP." A dev box on a
cloud VM, a LAN host the viewer shares a network with, a port-forward, or
a **tunnel** (Cloudflare Tunnel, ngrok, tailscale-funnel terminating
WSS) all qualify. For any of these, web-attach is just: the host adds a
browser-dialable listener, the browser dials the session peer id, done —
**the same way browser-IPFS connects to a public IPFS node.** This is
expected to be the common case and is the path to optimize for.

### Path B — Relayed (fallback, strictly-NAT'd hosts)

When the host has *no* public reachability at all and you won't give it
any, the browser and host need a middlebox both can reach. The browser
connects to a **relay over WSS**; the relay forwards the connection to
the host over **circuit-relay-v2**; the host holds a reservation on that
relay via its outbound connection:

```
browser ── WSS ──▶ relay ── circuit-relay-v2 (TCP/QUIC) ──▶ NAT'd host
```

The asymmetry to notice: **the host needs zero inbound reachability.** It
makes one *outbound* connection to the relay and reserves a slot
(AutoRelay / circuit-relay-v2 client); the browser, reaching the same
relay, is then routed `browser → relay → host` through the circuit. The
host only ever dialed out — so mosey instances can run *anywhere* with
outbound connectivity (no public IP, no UPnP, no port-forward). **The
single point of public ingress is the relay**, not the hosts.

This path **always relays** (no hole-punch upgrade — see
[below](#why-cant-we-just-use-public-infrastructure-the-helia-question)),
so the relay must be willing to carry the session for its whole lifetime.
**Public libp2p relays will not do this** (they are resource-limited by
design), so Path B requires a **self-run, sustaining relay** — shipped as
`mosey relay`. Because the data path stays relayed, the relay must lift
the default circuit-relay-v2 limits; a terminal's traffic is tiny
(keystrokes + screen diffs), so the bandwidth cost is negligible.

Because the relay is the *only* node that must be publicly reachable, it
is also the only place worth spending reachability effort — and a single
box is tractable in ways per-host reachability is not. It can be a VPS,
or **self-hosted behind a home router via UPnP / NAT-PMP or a manual
port-forward** — see [Self-hosting the relay](#4-mosey-relay--only-for-path-b).

> Note: "run a sustaining relay" and "put the host behind a tunnel" are
> the *same idea at different layers* — a thing both endpoints can reach.
> If you can do the tunnel (Path A), prefer it; it needs no mosey-specific
> infrastructure. Path B exists for when you can't touch the host's
> network at all.

## Why can't we just use public infrastructure? (the Helia question)

It is reasonable to ask: [Helia](https://github.com/ipfs/helia) runs a
full IPFS node in the browser and seems to reach the whole network using
only public infrastructure — so why does mosey need its own relay? Three
distinctions explain it, and together they show the relay is a narrow
fallback, not a fundamental requirement.

**1. Gateways are not relays; content retrieval is not a live
connection.** When browser-IPFS "just works," it is usually *not* making
a libp2p connection to the node that holds the data. It fetches the bytes
over plain **HTTPS from a gateway**, or finds providers via the IPFS
Foundation's public **delegated-routing HTTP endpoint**
(`delegated-ipfs.dev`). Helia ships exactly this: `@helia/verified-fetch`
defaults to `@helia/http`, "trustless HTTP gateways," with libp2p as one
option among several
([Helia verified-fetch](https://blog.ipfs.tech/verified-fetch/)).

**2. IPFS is content-addressed; a mosey session is not.** A block CID is
*replicated* across many providers, caches, and gateways — you don't care
*which* node serves it, only that *some reachable one* does. So Helia
connects to whatever subset of the network the browser can reach, and
that is enough. A mosey session is the inverse: a **live, stateful,
unique** PTY on **exactly one** host. No replication, no second provider,
no gateway that can cache "the live terminal of session X." Discovery
(DHT / delegated routing) tells you *where a peer claims to be* — it never
manufactures *reachability to it*. IPFS routes around unreachable nodes;
mosey cannot route around the one host you want.

**3. Public relays are hole-punch coordinators, not pipes.**
Circuit-relay-v2 is a **limited relay**: go-libp2p's defaults reset the
relayed stream after **2 minutes or 128 KB**, whichever comes first
([relay limits](https://pkg.go.dev/github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay)).
It was deliberately built *not* to be a TURN server — it relays just
enough to coordinate a **DCUtR hole-punch to a direct connection**, then
bows out. That is the trick IPFS browser↔browser leans on (brief relay →
hole-punch → direct), and it is precisely what mosey **cannot** do to a
go host:

> go-libp2p has **no relay-signalled `/webrtc` listener.** Verified
> against the source: its WebRTC transport advertises `Protocols() →
> []int{ma.P_WEBRTC_DIRECT}` and `CanDial` matches only WebRTC-**Direct**
> multiaddrs ([`transport.go`](https://github.com/libp2p/go-libp2p/blob/master/p2p/transport/webrtc/transport.go)).
> The relay-signalled `/p2p-circuit/webrtc` variant is a **js-libp2p
> browser↔browser** feature. WebRTC-Direct needs a *public* address, so it
> does not help a NAT'd host.

So a NAT'd go host can never be the *target* of a browser hole-punch.
With no hole-punch available, the only relayed option is a relay that
*sustains* the connection — and limited public relays will reset it. Hence
a self-run relay. This is a **current go-libp2p gap, not a permanent
one**: the day go-libp2p ships a relay-signalled WebRTC *listener*, mosey
could use limited public relays + hole-punch exactly like browser↔browser
IPFS, and the relay requirement would shrink to discovery + brief
signalling, which public infrastructure *can* provide.

The earlier framing of this proposal over-centered the relay. The honest
hierarchy is: **direct whenever the host is reachable at all (no relay) →
a self-run sustaining relay only for hosts you cannot make reachable.**

## Discovery: resolving a session id to an address

A viewer holds one **stable** identifier — the `session_key`, which is the
libp2p peer id, carried in the URL and durable across host restarts and
network moves ([resurrection](wallet-auth.md#session-identity-and-resurrection)).
What the browser must *dial* is a **current** multiaddr, and everything
about that is dynamic: the host's direct IP/port (Path A) or which relay
it sits behind and that relay's address (Path B). Discovery turns the
stable id into current, browser-dialable addrs **at connect time**, so
nothing dynamic is baked into the URL.

### Resolve is decoupled from relay

The two jobs are independent: *resolving* (peer id → addrs) is a separate
concern from *relaying* (carrying bytes for a NAT'd host). Keeping them
separate is what makes **the relay strictly optional** — an environment
where every host is directly addressable deploys no relay, and discovery
still works. The browser runs a **resolver chain**, trying sources in
order until one yields addrs that pass the handshake:

1. **URL hint.** If the fragment carries a current addr (`&addr=…` /
   `&relay=…`), dial it. Zero infrastructure, always available; the true
   no-infra baseline. Directly-addressable hosts usually have *stable*
   addresses (public DNS, fixed infra), so a hint like
   `#session=<id>&addr=/dns4/host.example/tcp/443/wss` barely rots.
2. **Rendezvous (if configured).** Query a directory for
   `resolve(session) → [addrs]`. **The relay doubles as this for free** —
   it already holds every reserved host's `identify` addr set — so a Path-B
   deployment gets rendezvous at no extra cost. A direct-only deployment
   simply configures none. The browser asks over a libp2p
   `/mosey/resolve/1.0.0` stream on the connection it already opens to the
   relay.
3. **Delegated-routing / DHT (if the host opts in).** A public fallback so
   `#session=<id>` *alone* resolves. See the caveat below.

The first source to return addrs the browser can actually reach wins; it
tries direct addrs (→ Path A) before any relay-circuit addr (→ Path B).

### Two layers: *which* sessions vs *where* a session is

The resolver chain above answers **"where is session X?"** It presumes you
already hold X's id. There is a layer above it — **"which sessions can I
reach at all?"** — and for wallet sessions the chain answers it directly.

**The chain is the directory of *which*.** The [on-chain program](wallet-auth.md#on-chain-program-anchor)
already records ownership and grants, so a connected wallet enumerates its
sessions with a plain RPC read — no libp2p, no signature, just the wallet's
public key (which the inline wallet flow already has):

- **Owned:** `getProgramAccounts(program, memcmp(owner, wallet))` →
  every `Session` this wallet owns; each carries its `session_key`.
- **Granted:** the same over `Grant` accounts filtered by
  `grantee == wallet` → the sessions this wallet was granted.

So the web app can present a **dashboard** — connect wallet → "here are
your terminals" → click to attach — instead of pasting ids. Three things
make this the right primitive for chain-persisted access:

- **It reuses a dependency mosey already commits to.** Reading the chain
  needs a Solana RPC, which the *server* already uses for snapshots and
  which browsers hit routinely. So it adds no new third-party dependency —
  and for chain sessions it **retires the delegated-routing (leg 3)
  concern**: the chain *is* the directory of which.
- **No new leak.** On-chain ownership / grants are already public; the app
  reading them exposes nothing the chain doesn't already.
- **Clean scope.** It covers *chain-persisted* access (owners + on-chain
  grants). Off-chain grants (bearer / `--to` blobs) aren't on chain, but
  they travel *with* their blob/URL — self-describing — so explicit `#id`
  remains the path for those and for any shared link.

(`getProgramAccounts` is heavy; some mainnet public RPCs throttle or
disable it. Devnet is fine; mainnet may want a paid RPC or an indexer — an
ops detail, not a blocker.)

**The chain also pins *which relay*, but never *where*.** The volatile host
address stays off-chain (it churns every restart) — but a **relay** is
stable infra, so an **optional `relay` field on the `Session` account** is
slow-changing on-chain data, exactly what the chain is for. It moves the
boundary by one notch without violating the [no-churn-on-chain rule](wallet-auth.md#discovery-stays-off-chain):

> **Chain (slow / stable):** who owns · who may attach · *which relay*
> **Off-chain (fast / volatile):** the host's *current* address

With it, the dashboard is **self-contained and multi-tenant**: each
`getProgramAccounts` row yields both the `session_key` *and* its relay, so
different owners can use different relays through one shared web app — no
baked-in default, no manual config. The chosen session's id is then
resolved to a live address through *that* relay's rendezvous (the chain
gave you *which* and *which-relay*; the resolver chain gives you *where*).

Adding the `relay` field is a small **program change** (a field on
`Session`, set at `register` / a new `set_relay`); call it out as such.

### Discovery is untrusted — Noise validates it

No resolver needs to be trusted, signed, or authenticated. Whatever it
returns is only a *hint*: the browser dials the candidates and the **Noise
handshake proves the remote holds `session_key`**. A lying or stale
resolver can only return addrs that fail Noise (rejected) or that point at
the real session (only the real host holds the key). So discovery can be a
dumb directory or an untrusted public service with no security cost.

### "DHT lookup" in a browser means delegated routing

A browser cannot meaningfully do raw DHT — it has no inbound, and public
DHT servers are mostly TCP/QUIC (the same reachability wall). So the DHT
leg is, in practice, a **delegated-routing HTTP endpoint** that runs the
`FindPeer` server-side (`GET /routing/v1/peers/<session>` → addrs — the
mechanism [Helia](https://github.com/ipfs/helia) uses via
`delegated-ipfs.dev`). Two honest consequences:

- It is **a dependency, not zero-infra** — a public delegated-routing
  service (a shared good, like a DNS resolver, but still third-party) or
  one you self-host — and it requires the host to **opt into publishing**
  its peer record to the public DHT, which advertises session liveness +
  addrs to a public index (the id is already public; the *liveness* is the
  new leak).
- So the genuinely infra-free option for a direct-only shop is the **URL
  hint**, with delegated routing as a *convenience* for sharing just the
  bare `#session=<id>`.

### CLI vs browser: same id, two resolvers

The Go CLI is a full libp2p node with kad-dht, so it resolves
`session_key → addrs` straight from the DHT (`FindPeer`) — the path
[the wallet-auth design already assumes](wallet-auth.md#session-identity-and-resurrection).
The browser adds the rendezvous + delegated-routing legs precisely because
it can't lean on the DHT the same way. One stable id, two resolver stacks.

### Mixed environments

A relay-rendezvous knows only the hosts reserved *on it*. In a deployment
mixing relayed and direct hosts, a directly-addressable host that never
touches the relay won't be in its directory — which is exactly why
discovery is a *chain*, not "relay else DHT": a direct host is found via
the URL hint or delegated routing, a relayed host via the relay. Each host
is discoverable through whatever it is set up for; the browser tries all
configured sources.

## Architecture

Path A (direct) and Path B (relayed) differ only in how the libp2p
connection is established; everything above the connection is identical.

```
   GitHub Pages (static, any origin)             Mosey host
   ┌──────────────────────────────┐              ┌─────────────────────────────┐
   │ mosey-web (static bundle)     │              │ mosey launch --wallet-...   │
   │  • js-libp2p node             │   Path A      │  • libp2p host              │
   │    - websockets / webtransport│◀────direct───▶│    peer_id == session_key   │
   │    - webrtc-direct            │  (host public)│  • Noise + yamux            │
   │    - circuitRelayTransport    │               │  • /mosey/{auth,pty,control}│
   │    - noise + yamux            │   Path B       │  • (Path B) AutoRelay resv. │
   │  • MoseyClient (libp2p Stream)│◀──┐ relayed    └───────────────┬─────────────┘
   │  • browser wallet (Phantom…)  │   │ (host NAT'd)               │ reserves a slot
   │  • xterm.js                   │   │                            ▼
   └──────────────┬───────────────┘   │            ┌──────────────────────────┐
                  │  WSS               └───────────▶│  mosey relay (self-run)   │
                  └────────────────────────────────│ • WSS listener (TLS)      │
                       all bytes relayed            │ • EnableRelayService      │
                       (terminal traffic — cheap)   │ • limits lifted           │
                                                    └──────────────────────────┘
       └──────────── Noise handshake is END-TO-END (browser ↔ host) ───────────┘
              on Path B the relay forwards ciphertext; it never sees the PTY
```

Identity and authorization, end to end (both paths):

- **Transport layer (Noise).** The browser dials the host's **peer id**,
  which equals the on-chain `session_key`. Noise proves the remote really
  holds that key — so "the server I reached *is* the session I asked for"
  is guaranteed by the transport, not merely asserted. (This subsumes the
  `expectSession` check the `wss://` path needs.)
- **Application layer (mosey auth).** The existing wallet handshake runs
  over the libp2p stream unchanged: the browser proves control of its
  connection key `K_c` and presents the delegation chain; the server
  folds it against its [on-chain snapshot](wallet-auth.md#snapshot-and-freshness)
  → `Identity` → caps. PSK and cert auth ride the same streams for
  non-wallet sessions.
- **The relay (Path B only) is untrusted.** It moves ciphertext between
  two endpoints whose Noise session is end-to-end. It learns the two peer
  ids and traffic timing, nothing more.

## Components to build

### 1. Host side — make the libp2p backend browser-dialable

[`transport/libp2p`](../../transport/libp2p/) today listens only on
`/tcp/0` + `/udp/0/quic-v1` and uses AutoRelay with the IPFS bootstrap
set — none of which a browser can reach. Additions (option-level, not new
transports for Path A):

- **Path A:** optional browser-dialable listen addrs — `/wss` (with the
  existing `--http-cert`/`--http-key`), `/webtransport`, and/or
  `/webrtc-direct`. Any one unlocks direct browser attach for a publicly
  reachable host.
- **Path B:** AutoRelay against a `mosey relay` so a NAT'd host holds a
  reservation a browser can route through. This mostly already exists
  (`EnableAutoRelayWithStaticRelays`); it needs to point at a
  browser-capable relay instead of the TCP/QUIC IPFS set.
- Surface the dial string (direct multiaddr, or relay-circuit multiaddr)
  in the host's printed `Endpoints()` so the operator can hand a viewer a
  complete address — or just the session id + a known relay/host addr.

No change to `vterm`, the auth wrap, or the protocol handlers — they are
already mounted on the libp2p host and dispatch per protocol id.

### 2. Browser side — a libp2p `Stream` for the TS client

The TS client's [`transport.ts`](../../clients/typescript/src/transport.ts)
opens one raw `WebSocket` per stream and correlates identity via a minted
`mosey-peer-<token>` subprotocol. Add a **second `Stream` implementation**
backed by js-libp2p:

- Bootstrap a browser libp2p node: `@libp2p/websockets`,
  `@libp2p/webtransport`, `@libp2p/webrtc` (for `/webrtc-direct` dials),
  `@libp2p/circuit-relay-v2` (transport, for Path B),
  `@chainsafe/libp2p-noise`, `@chainsafe/libp2p-yamux`.
- `Stream.open({ session, proto })` becomes
  `node.dialProtocol(sessionPeerId, proto)` — real multiplexed streams
  over one connection, so the per-stream WebSocket cost and the peer-token
  correlation kludge both disappear (peer id correlates natively).
- `MoseyClient.connect` gains a transport discriminant: `{ transport:
  "ws", endpoint }` (today) vs `{ transport: "libp2p", session, addrs }`
  (new, where `addrs` is a direct multiaddr or a relay-circuit multiaddr).
  Everything above `Stream` — `runWalletHandshake`, `runPSKHandshake`,
  PTY/control — is untouched.

### 3. The static web app

A standalone bundle (`webui/`, esbuild → embeddable / GitHub-Pages-able),
parameterized by the URL fragment so it ships generic:

```
# Path A (direct):
https://<pages-host>/#session=<base58 session_id>&addr=<host multiaddr>&caps=write
# Path B (relayed):
https://<pages-host>/#session=<base58 session_id>&relay=<relay multiaddr>&caps=write
```

The fragment never leaves the browser. The app:

1. Boots the libp2p node and dials the session peer id (directly, or
   through the relay).
2. Runs auth (wallet / PSK), opens the PTY + control streams.
3. Renders `xterm.js` + a fit addon; wires `onData` / `write` /
   `resize`; disables input when caps are view-only.

Assets (xterm + the mosey client + wallet glue) are bundled and served
from the static origin — no CDN, no third-party origin in the trust path.

### 4. `mosey relay` — only for Path B

A thin go-libp2p relay, needed only when hosts are strictly NAT'd:

- Listens on a **browser-dialable transport** for browsers (see the
  cert/domain trade below) and on `/tcp` + `/quic-v1` for hosts, which
  dial *out* to reserve.
- `EnableRelayService` (circuit-relay-v2 hop) **with the default
  duration/data limits lifted**, since Path B relays for the session
  lifetime rather than briefly coordinating a hole-punch.
- Stable identity (persisted key) so its multiaddr is durable and can be
  baked into the web app's default config, or pinned in a session's
  [on-chain `relay` field](#two-layers-which-sessions-vs-where-a-session-is).
- It never touches session *bytes* (Noise is end-to-end). In its default
  **open** mode it carries no mosey logic at all — pure ciphertext relay;
  the optional **locked** mode (below) adds chain-based *authorization*
  only, never byte access.

#### Self-hosting the relay (UPnP / NAT-PMP)

The relay is the *only* node that must be publicly reachable, so it is the
only place reachability effort is spent — and one box is far more
tractable than every host. It can be a VPS, or **self-hosted behind a home
router**: enable `libp2p.NATPortMap()` (UPnP + NAT-PMP) on the relay so it
requests its own external port, or set a manual port-forward. AutoNAT +
identify then learn and advertise the resulting public address. The mosey
hosts still need nothing inbound — they only dial out to this address.

UPnP gives the relay an `IP:port`, **not a domain or a CA cert**, so the
browser→relay transport choice carries a trade-off:

| Browser→relay listener | Domain + CA cert? | Survives a dynamic home IP? |
|---|---|---|
| **WSS** (`/dns4/<dyndns>/tcp/<port>/wss`) | **Yes** — but dynamic DNS (DuckDNS, …) + Let's Encrypt keeps the multiaddr string stable; only the IP behind the name moves | **Yes** — DNS absorbs IP changes |
| **WebRTC-Direct** (`/ip4/<ip>/udp/<port>/webrtc-direct/certhash/…`) | **No** — certhash rides in the multiaddr; no CA, no domain | **No** — an IP change rewrites the dial string |

So **WSS + dynamic DNS** is the robust home-relay setup (stable address
across IP changes, at the cost of standing up dyndns + an ACME cert),
while **WebRTC-Direct** is the zero-domain / zero-CA quick path that is
brittle to a dynamic IP (best with a static IP). The WebRTC-Direct →
relay → circuit path is sound in principle but less battle-tested than
WSS-relay — spike it before relying on it.

Caveats, now scoped to this one box rather than every host:

- **CGNAT defeats it.** If the relay's line sits behind carrier-grade NAT,
  UPnP opens a port that is still private upstream and unreachable. This is
  the main "UPnP supported ≠ UPnP works" failure — but you only have to
  verify it once, for the relay (compare the router's WAN IP to your
  observed public IP).
- **All session bytes cross the relay's uplink.** Negligible for terminal
  traffic; the bound only bites with many concurrent sessions on a home
  line.
- **It is an exposed service.** The relay forwards ciphertext only (no app
  logic, no LAN access beyond the process), but it is still an open port —
  sandbox it and keep per-peer reservation / connection caps on even with
  the data/time limits lifted.

#### Access control: open relay vs locked relay (opt-in)

By default a circuit-relay-v2 relay is **open** — any peer may reserve or
route through it (bounded only by resource limits). Lockdown then comes
solely from each session's own end-to-end auth. That is the right default
for a shared / community relay.

For a **private** relay ("only my wallet's fleet may use my relay"), the
relay opts in to **chain-gated access control** via go-libp2p's relay
`ACLFilter` ([`AllowReserve` / `AllowConnect`](https://github.com/libp2p/go-libp2p/blob/master/p2p/protocol/circuitv2/relay/acl.go),
wired with `relay.WithACL`). The key realisation: "locked down" is the
relay *refusing* unauthorized peers — an authorization mechanism, **not**
hiding the relay's address (knowing the address grants nothing if the relay
rejects you; and browser wallets can't decrypt an obscured one anyway). The
relay authorizes against the **same on-chain program** the host reads, so
no static allowlist is needed:

- **`AllowReserve(peer, addr)` — gate the hosts.** A reserving host's peer
  id *is* its `session_key`, already cryptographically proven by Noise. The
  relay checks the chain: is `peer` a `Session` whose `owner ∈ {configured
  wallet(s)}`? If yes, allow; else refuse. → **Only your wallet's sessions
  can reserve**, auto-updating as you register / transfer sessions.
- **`AllowConnect(src, srcAddr, dest)` — gate the routing.** Restrict
  `dest` to the relay's authorized sessions, so it only ever forwards
  *toward* your fleet.

This reuses the existing [`walletsolana`](../../walletsolana/) snapshot
machinery (watch `getProgramAccounts(owner=W)` + `accountSubscribe`) the
host already uses — the relay just maintains a cached set of authorized
`session_key`s. It is enabled by an explicit flag (e.g.
`mosey relay --owner <wallet>`); absent the flag the relay stays open.

**The viewer-side residual.** `AllowConnect` sees the *viewer's* peer id
(`src` = the browser's ephemeral `K_c`), which is **not** a wallet and not
on chain — the mosey wallet handshake is end-to-end (Noise ciphertext,
opaque to the relay). So a locked relay can restrict *destinations* to your
sessions, but cannot tell *which wallet* a browser is. An unauthorized
browser could still route toward your session and then be **rejected by the
session's own auth** (no grant) — the relay carries only a few handshake
bytes before that, bounded by per-`src` rate limits. No access is granted.
For a purely personal relay whose sessions grant only your wallet, that is
effectively "only you can use it." If even *carrying* an unauthorized
browser is unacceptable, an opt-in **strict** tier adds a small
mosey-specific relay-auth step (the browser proves a wallet grant to the
relay before `AllowConnect`); deferred unless the residual matters.

**Design shift to note.** A locked relay is **mosey-aware**: it reads the
program (needs an RPC endpoint + program id) and authorizes by wallet —
unlike the open relay's pure byte-forwarding. It still never sees session
bytes. So `mosey relay` has two postures: **open** (stock, dumb) and
**locked** (`--owner`, chain-gated) — opt-in, off by default.

### 5. Wallet auth, inline in the browser

The CLI wallet flow is a **loopback hand-off**: `mosey attach` spins up a
`127.0.0.1` server, opens a browser to sign a `wallet → K_c` delegation,
posts it back, then handshakes. **In the browser, the wallet and the
attach client share one page, so the loopback collapses** — the page does
both halves itself:

```
app loads  #session=<id>&caps=write
  │
  ├─ IndexedDB cache hit (session, wallet) → {K_c, chain} still valid? ─yes─▶ handshake
  no
  │
  ├─ detect injected wallet (Phantom/Solflare/Backpack) → provider.connect()
  ├─ mint NON-EXTRACTABLE K_c   (WebCrypto Ed25519, in-page)
  ├─ render canonical delegation content  (wallet-delegation.ts → byte-identical to Go)
  ├─ wallet.signMessage(contentBytes)      ← the ONLY wallet prompt, once per grant-lifetime
  ├─ chain = [ Delegation{ content, sig } ]   (one-hop wallet→K_c == the on-chain path)
  ├─ cache {K_c handle, chain} in IndexedDB  (TTL = delegation not-after)
  ▼
 MoseyClient.connect({ transport:"libp2p", session, addrs,
     auth:{ type:"wallet", connKey:K_c, delegationChain:chain } })
  server folds chain → snapshot owner/grant caps → Identity → PTY → xterm
```

Browser-specific refinements over the CLI path:

- **`K_c` is a non-extractable `CryptoKey`** held in IndexedDB, not raw
  bytes in `localStorage`. Reconnects / reloads reuse it with no wallet
  prompt; script cannot exfiltrate the private key; blast radius is
  bounded by the granted caps and a short `not-after`. This requires one
  small generalization of `runWalletHandshake`: accept a signer
  (`(msg) => Promise<sig>`) instead of only a 64-byte `connKey`.
- **The grant cache is the browser analog of `~/.mosey/grants/`**, keyed
  `(session, wallet)`, TTL = the delegation's `not-after`.
- **Wallet-less viewers** (bearer or `--to` off-chain grants) are a
  secondary path: import the delegation chain via a pasted blob / URL
  fragment / QR. The wallet-bound (`--to`) case appends one in-browser
  `viewerWallet → K_c` sub-delegation. Deferred past the owner /
  on-chain-grant inline path.

## Security

- **Session authenticity is transport-enforced.** `peer_id ==
  session_key`; Noise proves it. A MITM (including a Path-B relay) cannot
  impersonate the session.
- **The relay (Path B) is untrusted.** Noise is end-to-end between
  browser and host, so the relay never sees PTY bytes, secrets, or `K_c`.
  It learns peer ids and timing.
- **`K_c` non-extractable + short `not-after`.** The persisted credential
  is a capability-bounded, time-bounded, non-exfiltratable key.
- **Caps are enforced server-side** from the on-chain snapshot ∩ the
  presented chain, regardless of what the app requests. View-only is
  enforced by the server; the UI merely reflects it.
- **TLS is mandatory for the browser-facing hop** — `/wss` direct, or the
  relay's `/wss` listener (browsers won't open `ws://` from an `https://`
  origin).
- **The web app is a fixed bundle** served from its own origin; it injects
  no server-controlled HTML. The session id in the fragment is public (it
  is the on-chain id).
- **Relay DoS surface** (Path B): even with session-lifetime limits
  lifted, keep per-peer reservation caps and connection-count limits so
  the relay can't be exhausted; tune for the deployment.

## Where it plugs into the code

- [`transport/libp2p`](../../transport/libp2p/) — Path A: optional `/wss`,
  `/webtransport`, `/webrtc-direct` listen addrs. Path B: AutoRelay against
  a browser-capable relay. Surface the dial string in `Endpoints()`.
- [`clients/typescript/src/transport.ts`](../../clients/typescript/src/transport.ts)
  — a libp2p-backed `Stream` implementation alongside the WebSocket one;
  a browser libp2p node bootstrap helper; a **resolver chain** (URL hint →
  `/mosey/resolve/1.0.0` rendezvous → delegated-routing HTTP) that maps a
  `session_key` to candidate addrs, with Noise validating on dial.
- [`clients/typescript/src/client.ts`](../../clients/typescript/src/client.ts)
  — a `transport` discriminant in `ConnectOptions` (`"ws"` | `"libp2p"`).
- [`clients/typescript/src/wallet-auth.ts`](../../clients/typescript/src/wallet-auth.ts)
  — accept a non-extractable signer for `K_c` in addition to raw bytes.
- `webui/` (**new**) — the standalone static app (xterm + wallet-inline +
  IndexedDB grant cache), an esbuild bundle, a GitHub Pages deploy. Plus a
  **wallet dashboard**: `getProgramAccounts` by `owner` / `grantee` to list
  the connected wallet's sessions and read each session's on-chain `relay`.
- `cmd/mosey/relay.go` (**new, Path B only**) — `mosey relay`: a go-libp2p
  relay with a browser-dialable listener (WSS or `/webrtc-direct`) +
  `/tcp` + `/quic-v1` for hosts + `EnableRelayService` (limits lifted) +
  persisted identity, plus an opt-in **`libp2p.NATPortMap()`** so the relay
  can self-expose behind a home router via UPnP / NAT-PMP. Also serves the
  **`/mosey/resolve/1.0.0`** rendezvous, answering `session → addrs` from
  the `identify` addr sets of hosts reserved on it (no extra state). An
  opt-in **`--owner <wallet>`** [locked mode](#access-control-open-relay-vs-locked-relay-opt-in)
  wires `relay.WithACL` (chain-gated `AllowReserve` / `AllowConnect`) over a
  reused `walletsolana` snapshot; off by default (open relay).
- [`programs/mosey-session`](../../programs/) — add an optional `relay`
  field to the `Session` account, set at `register_session` / a new
  owner-only `set_relay`; emit it in the events the snapshot follows.
- [`walletsolana`](../../walletsolana/) — an owner-indexed query
  (`getProgramAccounts(memcmp owner)`) for the relay's ACL snapshot and the
  web dashboard; decode the new `relay` field.
- `cmd/mosey/launch.go` — browser-dialable `--listen` schemes (Path A);
  a `--relay <multiaddr>` flag feeding AutoRelay (Path B). Hosts need no
  inbound reachability for Path B — the `--relay` reservation is outbound.
  An opt-in `--advertise-dht` makes the host publish its peer record so the
  delegated-routing resolver leg can find it (off by default — it leaks
  session liveness to the public DHT).
- `justfile` — a `web-build` recipe; relay build/run targets.
- Docs — this file; a `mosey relay` entry in [the CLI surface](cli.md).

## Phasing

```
P0  ── Direct vertical slice (Path A — the common case) ──────────────
      host: browser-dialable /wss (or webtransport / webrtc-direct)
      browser: libp2p Stream + node bootstrap
      static app: xterm + PSK auth over libp2p, direct dial
      ✦ demoable: open the page → reach a publicly-reachable host, no relay

P1  ── Wallet inline ─────────────────────────────────────────────────
      non-extractable K_c signer; IndexedDB grant cache
      inline wallet → K_c delegation; view-only affordances
      ✦ the full ttyd-with-wallet experience

P2  ── Strictly-NAT'd hosts (Path B) ─────────────────────────────────
      mosey relay (WSS + relay service, limits lifted)
      host: AutoRelay against it; browser: circuitRelayTransport
      ✦ reach a host with zero public reachability

P3  ── Chain-driven discovery + locked relay ─────────────────────────
      Session.relay field (program change); wallet dashboard
        (getProgramAccounts by owner/grantee → which + which-relay)
      mosey relay --owner (opt-in chain-gated ACL, reuses walletsolana)
      ✦ connect wallet → pick a terminal; private relays per owner

P4  ── Reach + ergonomics ────────────────────────────────────────────
      wallet-less viewers: bearer / --to import (paste / URL / QR)
      relay provisioning story (hosted default, --relay override)
      reconnect / pty-resume in the browser; optional strict relay-auth tier
```

The critical path to a working browser attach is **P0**, and it needs
**no relay at all** — just a browser-dialable listener on a reachable
host, exactly the way browser-IPFS reaches a public node. The relay
(P2) is a self-contained add-on for the strictly-NAT'd case, and the
hard, fragile parts (WebRTC signalling, hole-punching, a custom relay
protocol) are designed *out* throughout — see
[the Helia question](#why-cant-we-just-use-public-infrastructure-the-helia-question).

## Open questions

- **Path B relay provisioning.** Run-your-own only, a project-hosted
  default for the devnet tier, or both behind `--relay`? (Leaning: both —
  a default for friction-free devnet use, override for self-governed
  deployments, mirroring the [program-id posture](wallet-auth.md#deployment--governance).)
  A self-run relay can be a VPS or [self-hosted behind a home router via
  UPnP / NAT-PMP](#self-hosting-the-relay-upnp--nat-pmp); whether to wire
  `NATPortMap()` on by default for `mosey relay` (vs. opt-in) is open.
- **Discovery** — the resolver chain (URL hint → rendezvous → delegated
  routing) is settled; see [Discovery](#discovery-resolving-a-session-id-to-an-address).
  What's still open: *which* delegated-routing endpoint to default to (a
  public one vs. none), whether host DHT-publish is opt-in or off by
  default (the liveness-leak trade), and whether the web app ships a baked
  default rendezvous/relay multiaddr. For a UPnP/dynamic-IP relay, prefer a
  `/dns4/<dyndns>/…/wss` rendezvous multiaddr (stable across IP changes)
  over a raw-IP `/webrtc-direct` one so a baked/shared address doesn't rot.
- **Locked-relay viewer residual.** A chain-gated relay can restrict
  *destinations* to your sessions but can't see a *viewer's* wallet
  (`AllowConnect` sees the ephemeral `K_c`, and the wallet handshake is
  end-to-end). Is "an unauthorized browser is carried a few handshake bytes,
  then rejected by the session's auth" acceptable (simplest), or is the
  opt-in [strict relay-auth tier](#access-control-open-relay-vs-locked-relay-opt-in)
  worth building? Default: accept the residual; build strict only on demand.
- **Keep the `wss://` direct client?** Yes — the existing raw-WebSocket
  `MoseyClient` is retained as a same-network fast path; the libp2p path
  is the decoupled default.
- **Tunnel guidance.** Since a tunnel (Cloudflare/ngrok/tailscale-funnel)
  turns a NAT'd host into a Path-A host with no mosey-specific infra,
  document it as the recommended alternative to running a relay.
```
