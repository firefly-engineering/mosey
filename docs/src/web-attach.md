# Browser web-attach (proposal)

> **Status: design proposal.** Nothing here is implemented yet. This
> document designs a [ttyd](https://github.com/tsl0922/ttyd)-equivalent:
> attach to a running `mosey launch` from a web browser — **and manage the
> session** (transfer ownership, grant / revoke access, …) — with on-chain
> [wallet auth](wallet-auth.md) deciding what you may attach to and govern.
> It is a **self-hosted web gateway**: a small service you run that is a
> full libp2p node *and* a web terminal *and* a management console,
> reached from your browser over a VPN (Tailscale).
>
> This **supersedes** two earlier drafts, preserved in git history:
> a *browser-as-full-libp2p-node* design (`docs(web-attach): add browser
> web-attach design proposal`) and a *static-page + personal wallet-bound
> agent* design (`docs(web-attach): rework around a personal wallet-bound
> libp2p agent`). Both fought the browser's libp2p limitations and ended
> up requiring browser-reachable relays. This revision sidesteps all of
> it by keeping libp2p entirely server-side and solving browser
> reachability with a VPN instead of relays.

## The one idea

Run a small **web gateway** — one container on a box you control — that
is simultaneously:

- a **full libp2p node** that dials `mosey` hosts exactly the way
  `mosey attach` already does, and
- a **web terminal server** that serves `xterm.js` to your browser.

Your browser reaches the gateway over **Tailscale** (or any VPN); the
gateway reaches `mosey` sessions over libp2p. The browser never speaks
libp2p, and **you maintain no relays.**

```
   browser (roaming)              your web gateway (one container)            a mosey host
   ┌──────────────────┐  Tailscale ┌─────────────────────────────┐   libp2p   ┌──────────────┐
   │ • xterm.js        │  HTTPS/WS │ • full libp2p node (≈attach) │  direct,   │ launch       │
   │ • wallet connect  │◀─────────▶│ • web terminal server        │  or public │ peer_id ==   │
   │ • no libp2p       │ (private,  │ • runs wallet handshake      │  swarm +   │  session_key │
   │ • no key storage  │  no public │   to hosts on your behalf    │  DCUtR     │              │
   └──────────────────┘  exposure) └─────────────────────────────┘◀──────────▶└──────────────┘
```

## Why this removes the relay problem

Every relay headache in the earlier drafts came from one fact: **the
browser was the libp2p endpoint, and browsers can't use the normal
libp2p relay swarm** — they can't dial TCP/QUIC relays, can't hole-punch,
and go-libp2p has no relay-signalled WebRTC listener for them. So you had
to stand up *special, browser-reachable* relays and keep them running.

Moving the libp2p endpoint to a **full node** (the gateway) dissolves
that. A full node has the same connectivity `mosey attach` has today:

- **Host on your tailnet / LAN** → the gateway dials it **directly**. No
  relay, no DHT, no hole-punch.
- **NAT'd host elsewhere** → reached with mosey's **existing** machinery:
  the host sits on the **public libp2p relay swarm** (mosey's default
  bootstrap) for NAT mediation, and the gateway **DCUtR-hole-punches to a
  direct connection** — identical to `mosey attach`. You run and maintain
  *none* of that.

So the only thing you operate is the gateway, and **Tailscale** carries
your browser to it across networks with no public exposure and no TLS
chores (`tailscale serve` gives you HTTPS + MagicDNS automatically). The
VPN replaces "expose a public endpoint + manage certs + run relays" with
"be on your tailnet."

## What it costs

- You **self-host one service** (a container) — but exactly one, and no
  relays.
- Access is a **private gateway**, not "open to any browser with your
  wallet": a client must be on a tailnet that can reach the gateway. That
  is the deliberate trade for dropping relays and public exposure.
- The gateway is a **trusted node**: it terminates the connection to
  hosts (sees PTY plaintext) and uses a wallet delegation to attach. It
  is *yours*, on *your* box, so that is acceptable — but it is the
  defining trust boundary (see [Security](#security)).

## What already exists (and is reused)

The gateway is, deliberately, mostly assembled from parts that already
work:

| Piece | Status | Role in the gateway |
|---|---|---|
| `mosey attach` libp2p client + wallet handshake | done | the gateway's **host-facing** half — it *is* an attacher |
| WebSocket transport + TS `MoseyClient` | done | the gateway serves `/mosey/{auth,pty,control}` to the **browser** over WS; the browser drives it with the existing `MoseyClient` ([`xterm-demo.html`](../../clients/typescript/examples/xterm-demo.html)) |
| Canonical delegation + inline `signMessage` | done | the browser signs the delegation the gateway presents to hosts |
| [`walletsolana`](../../walletsolana/) snapshot | done | chain reads for the session dashboard |

The host side does **not change**: a host is already a libp2p node with
`peer_id == session_key`, authenticating attachers with the wallet
handshake. The gateway is just another attacher.

## Reachability: the VPN front

The gateway is **VPN-agnostic** — it is a plain HTTP/WS server (bound to
localhost or the tailnet interface); how the browser reaches it privately
is the operator's choice, not baked into mosey.

There is one **hard constraint**, though: browser wallets
(Phantom / Solflare / Backpack) only inject and sign in a **secure
context** — `https://` or `http://localhost`. A plain-`http` tailnet IP
will not work. So whatever fronts the gateway **must terminate HTTPS.**

- **Tailscale (recommended default).** `tailscale serve` terminates HTTPS
  with a real Let's Encrypt cert for the box's MagicDNS name and proxies
  to the gateway's local port — secure context, no cert chores, NAT
  traversal for roaming clients, all for free.
- **Headscale** — the same, with a self-hosted control plane (no third
  party).
- **Generic** — any reverse proxy / VPN that provides HTTPS in front of
  the gateway works; the gateway doesn't care.

## The browser side

A normal web client — **no libp2p, no key storage:**

- loads the UI from the gateway over Tailscale HTTPS,
- **wallet connect** (Phantom / Solflare / Backpack) for authorization,
- a **session dashboard** (the chain read — see [Discovery](#discovery)),
- `xterm.js`, driven over a WebSocket to the gateway with the existing
  `MoseyClient`,
- **management controls** — transfer ownership, grant / revoke access,
  bump epoch (see [Session management](#session-management-governance)).

The browser holds nothing but the current WS session.

## Authentication and authorization

Two independent gates, and **Tailscale is only the outer one:**

- **Network perimeter — Tailscale.** Decides *who can reach the gateway*
  (device-level). It does **not** satisfy a host.
- **Session authorization — wallet + chain.** A wallet-launched host
  *demands* a valid delegation to attach, regardless of the network. So
  on login the browser runs the inline `signMessage` to authorize the
  gateway, and the gateway presents that to the host. Caps are enforced
  **at the host** (snapshot ∩ presented chain), unchanged.

Concretely, per browser login: the gateway mints an **ephemeral key
`K`**, the browser wallet signs **`W → K`** once, and the gateway uses
`K` to attach to that user's sessions for the life of the login,
discarding it on logout. There is no standing credential — without a
fresh, scoped `W → K` delegation the gateway's `K` is useless. (This is
the `K_c` mechanism from the wallet-auth design, held gateway-side per
login instead of in the browser.)

The delegation is **scoped tight**: caps `{write, resize}` for an
interactive attach (or `{}` for a view-only one — a per-attach toggle),
and **never `forge`** — the gateway has no business re-delegating access.
Its `not-after` defaults to **~12–24h** (`--delegation-ttl`). Because
expiry gates only *new* handshakes (a live attach keeps running past it,
per the wallet-auth model), the user re-signs only on **reconnect /
resume**, never mid-session.

### Multi-user

The gateway is a **multi-user / team service**: whoever logs in supplies
their own `W → K`, and the gateway attaches with *their* on-chain access,
so each user sees only their own sessions. That makes a few things
load-bearing:

- **Per-connection isolation.** All attach state (`K`, streams, PTY
  bytes) is scoped to one logged-in WS connection; nothing is shared
  across users. Two users attaching the *same* session is the **host's**
  existing [multi-client](multi-client.md) concern, not the gateway's —
  the gateway just multiplexes independent connections.
- **Per-user resource limits.** Cap concurrent attaches / streams per
  wallet so one user can't exhaust the gateway.
- **Two gates, defense in depth.** Tailscale ACLs decide which *devices*
  reach the gateway; the wallet + chain decide which *sessions* a user
  may attach. A tailnet device with no valid delegation can reach the
  gateway but attach to nothing — there is no ambient authority.
- **Trust surface.** A shared gateway holds several users' `K`s and sees
  several users' plaintext, so it is trusted by its whole team; keep each
  `K` ephemeral-per-login, scope the delegations, and sandbox the process.

## Discovery

- **Which sessions (the menu).** `getProgramAccounts` keyed by the
  connected wallet — owned (`memcmp(owner, W)`) and granted
  (`Grant.grantee == W`). The browser or the gateway runs it; it reuses
  the Solana RPC the project already depends on.
- **Where the host is.** The **gateway** resolves it like any libp2p
  node: a tailnet/LAN address directly, or `FindPeer(session_key)` over
  the DHT — which returns the host's current addresses (direct *or*
  relay-circuit) the normal way. The browser resolves nothing.

This means **no on-chain address data and no program change.** The
boundary is simply **chain = who owns · who may attach; off-chain = the
host's current address, via the DHT.** (An earlier draft proposed an
on-chain `Session.relay` pointer; `FindPeer` makes it redundant.)

> Implementation note: mosey does **not** resolve a bare peer id today —
> the libp2p backend bootstraps a kad-DHT but never wires it into dialing
> (`b.host` is the raw host, not a `RoutedHost`, and the DHT handle isn't
> retained — `transport/libp2p/libp2p.go`). So the gateway's dialer needs
> a small addition: `dht.FindPeer(session_key)` before `Connect` (or wrap
> the host as a `RoutedHost`). A configured-address escape hatch covers
> P0 / tailnet hosts before that lands.

## Session management (governance)

The web frontend is not only a terminal — it is also a **management
console** for the sessions a connected wallet owns. The same wallet
that authorizes attachment also drives the on-chain
[program operations](wallet-auth.md#on-chain-program-anchor), which the
CLI already exposes as `mosey session …` / `mosey grant`:

| Control | Mechanism | Wallet action |
|---|---|---|
| **Transfer ownership** | `transfer_ownership(new_owner)` | signs a **transaction** |
| **Grant (on-chain)** | `grant(grantee, caps, expiry)` — nothing to deliver, grantee attaches with just their wallet | signs a **transaction** |
| **Grant (off-chain)** | a `W → grantee` delegation blob / URL / QR (bearer or `--to`) | signs a **message** (`signMessage`) |
| **Revoke** | `revoke(grantee)` (closes the Grant PDA) | signs a **transaction** |
| **Bump epoch** | `bump_epoch()` (mass-revoke) | signs a **transaction** |
| **Register** | `register_session` — usually done at launch, optionally here | signs a **transaction** |

The crucial property: these are **signed by the owner's wallet directly
in the browser** — Phantom et al. sign Solana *transactions*, not just
messages. So the **gateway never holds owner authority**: it only *builds
the unsigned transaction* (reusing [`walletsolana`](../../walletsolana/)'s
existing hand-rolled `TransferOwnership` / `Grant` / `BumpEpoch` /
`RegisterSession` builders), hands it to the browser for the wallet to
sign, and submits it. The off-chain grant reuses the canonical-delegation
`signMessage` flow already in the loopback signer.

Because each user only ever sees and governs the sessions their wallet
owns (the dashboard is keyed by wallet), governance is per-user in the
multi-user gateway with no extra isolation work.

## Hosts and NAT

A host needs **no browser-facing transport and no new inbound** beyond
what `mosey` already does:

- **On your tailnet / LAN** → the gateway dials it directly.
- **NAT'd elsewhere** → it relies on mosey's existing AutoRelay + public
  swarm for mediation; the gateway hole-punches to direct. The public
  relay only ever sees **ciphertext** (gateway↔host Noise is end-to-end).

There is no 1:1 relay relationship and nothing host-specific to provision
for the web path.

## Grantees

Each participant runs **their own** gateway on **their own** tailnet. A
grantee connects their wallet to their gateway, which attaches to your
session over libp2p (direct or public-swarm-mediated); the host
authorizes them via their **on-chain grant**. They never touch your
gateway or your tailnet — the same "no shared infra, no 1:1" property as
the agent model, with even less to run.

## Security

- **The gateway is a trusted node** (yours): it sees your PTY plaintext
  and wields `W → K`. Keep `K` ephemeral-per-login, keep the `W → K`
  delegation **short-lived and least-cap**, and sandbox the container.
- **Session authenticity is transport-proven** — `peer_id ==
  session_key`, Noise proves the gateway reached the real session.
- **Caps are enforced at the host**, not the gateway or browser.
- **Defense in depth:** Tailscale gates the device, the wallet gates the
  session; neither alone is the whole story.
- **Public relays (when used) see only ciphertext.**

## Where it plugs into the code

- `cmd/mosey/web.go` (**new**) — `mosey web`: the gateway. Reuses the
  [`attach`](../../attach/) libp2p client + wallet handshake to reach
  hosts, and serves an HTTP/WS endpoint (UI + the `/mosey/*` streams) to
  the browser. Mints `K` per login, runs the host handshake with the
  browser-supplied `W → K`, scopes all attach state per WS connection
  (multi-user isolation), and enforces per-wallet resource limits.
- `webui/` (**new**) — the web UI: xterm + wallet connect + dashboard +
  the **management console** (transfer / grant / revoke / bump). The
  browser↔gateway terminal path reuses `MoseyClient`'s WebSocket transport
  as-is; new code is wallet-login, the dashboard, and the governance forms.
- **Gateway governance endpoints** — `mosey web` builds *unsigned*
  transactions for transfer / grant / revoke / bump / register (reusing
  [`walletsolana`](../../walletsolana/)'s existing builders), returns them
  for the browser wallet to sign, and submits the signed result. The
  off-chain grant reuses the canonical-delegation `signMessage` path. The
  gateway never holds owner authority.
- [`transport/libp2p`](../../transport/libp2p/) — wire the DHT into
  dialing so the gateway can resolve a bare `session_key`
  (`dht.FindPeer` / `RoutedHost`); not done today (see the
  [Discovery](#discovery) note).
- [`clients/typescript`](../../clients/typescript/) — browser-side login,
  dashboard, and governance glue; the transport layer is unchanged.
- [`walletsolana`](../../walletsolana/) — owner/grantee-indexed
  `getProgramAccounts` for the dashboard; the tx builders are reused for
  governance.
- **Deployment** — a `Dockerfile` for `mosey web` and a short runbook for
  `tailscale serve` (HTTPS + MagicDNS); `Headscale` noted for a
  no-third-party tailnet.

What this design **drops** versus the superseded drafts: js-libp2p in the
browser, browser-side `K_c` + IndexedDB, all WebRTC/transparent-relay
machinery, any user-maintained relays, and the on-chain `Session.relay`
pointer (a `FindPeer` makes it redundant).

## Phasing

```
P0  ── Gateway against a reachable host ──────────────────────────────
      mosey web: libp2p attach to a tailnet/LAN host + serve xterm/WS
      browser: wallet login (W→K) + xterm over MoseyClient
      reach it over Tailscale
      ✦ open the page on your tailnet → wallet login → a terminal

P1  ── Hosts elsewhere ───────────────────────────────────────────────
      gateway inherits attach's public-swarm + DCUtR path to NAT'd hosts
      ✦ reach a session running anywhere, no relays you maintain

P2  ── Chain-driven discovery + multi-user ───────────────────────────
      gateway wires DHT FindPeer (resolve a bare session_key)
      wallet dashboard (which sessions); per-connection isolation +
        per-wallet resource limits
      ✦ connect wallet → pick a terminal; team-ready

P3  ── Governance console ────────────────────────────────────────────
      transfer / grant (on- + off-chain) / revoke / bump-epoch in the UI
      gateway builds unsigned txns; wallet signs; gateway submits
      ✦ manage sessions from the browser, owner authority stays in the wallet

P4  ── Ergonomics ────────────────────────────────────────────────────
      grantee flows end-to-end; reconnect / pty-resume in the UI
```

P0 is small — it is `mosey attach` to a reachable host with a web
front-end, behind your VPN. Everything after is additive.

## Implementation status

Built and tested in this repo (`go test ./...`):

| Area | What landed | Verification |
|---|---|---|
| P0 bridge | `mosey web`: embedded xterm SPA + per-WS `attach.Run` bridge (binary frames = PTY, JSON resize control); `attach.Options.ResizeC` for non-TTY size; shared `buildClientTransport` | e2e: browser-style WS through the gateway echoes through a `cat` host (unix socket) |
| Discovery (where) | libp2p `RoutedHost` so `Dial` resolves a bare `/p2p/<session-key>` via `dht.FindPeer` | `parseEndpoint` tests (bare + full forms) |
| Wallet login | `--wallet-login`: `/login/prepare` mints `K` + renders the `W→K` delegation, `/login/callback` verifies the wallet signature and builds a per-login `auth.Wrap`; `/config`-driven browser sign flow; caps default view-only, never `forge`; `--delegation-ttl` ~16h | e2e: a local key signs the delegation; attach echoes over the authorized WS |
| Dashboard (which) | `walletsolana.SessionsByOwner` — owner-indexed `getProgramAccounts` listing a wallet's sessions | unit (fake RPC) |
| Dashboard + multi-session | `--wallet-rpc`/`--wallet-program` mode: `/sessions` endpoint, `session_key → /p2p/<peer-id>` target, per-login session selection (dial the chosen session via the DHT), browser session picker | unit (`sessionTarget`, `/sessions` with a fake lister) |
| Governance: off-chain grant | `/grant/prepare` + `/grant/callback`: owner signs an `owner → grantee` delegation in the page (`signMessage`), gateway returns the encoded chain blob; UI "Grant access" control | unit (owner signs; blob decodes + verifies) |
| Governance: on-chain writes | `walletsolana` unsigned-tx builders (`BuildTransferOwnership` / `BuildGrant` / `BuildRevoke` / `BumpEpoch`, shared ix builders) + `SubmitSigned`; gateway `/govern/build` + `/govern/submit`; UI "Manage…" → web3.js `signTransaction` → submit. The gateway only builds + submits; the owner wallet signs. | unit (`compileUnsignedTx` == signed-minus-sig; `/govern` routing with a fake governor). **Browser signing + submission verified on devnet, not in CI.** |

Remaining (not yet built):

- **Grantee listing** — the dashboard lists *owned* sessions; granted
  ones need the extra `Grant → Session` hop (`getProgramAccounts` on
  grantee, then resolve each Grant's session).
- **Multi-user resource limits**, and **vendoring xterm.js / web3.js**
  for offline (both load from a CDN today).
- **Multi-user hardening** — per-wallet resource limits; the per-WS
  isolation is structural already.
- **Offline assets** — xterm.js is loaded from a CDN; vendoring it into
  the embed is a follow-up.

## Decisions made

- **Multi-user / team gateway** (not single-user) — per-login `W → K`
  scopes each user to their own sessions; the gateway adds per-connection
  isolation + per-wallet resource limits.
- **`W → K` scope:** caps `{write, resize}` (or `{}` view-only), **never
  `forge`**; `not-after` default **~12–24h** (`--delegation-ttl`),
  re-signed on reconnect (a live attach outlives expiry).
- **VPN:** gateway is VPN-agnostic plain HTTP/WS; the front **must
  terminate HTTPS** (wallets need a secure context). Tailscale
  (`tailscale serve`) is the recommended default; Headscale / any HTTPS
  reverse proxy also work.
- **No `Session.relay` / no program change for discovery** — the gateway
  resolves `session_key` via `dht.FindPeer` (needs wiring; see Discovery).
- **No-VPN / public-gateway tier is a non-goal** — it would reintroduce
  the public exposure + browser-relay problems this design removed.

## Open questions

- **Per-wallet resource-limit policy.** Concrete caps (concurrent attaches
  / streams, RPC rate) for a shared gateway.
- **Long-session expiry UX.** A live attach outlives `not-after`, but
  reconnect/resume needs a fresh `W → K`; how/when to prompt without
  surprising the user mid-work.
- **Governance UX depth.** Which ops to surface first (transfer + grant
  are the obvious P3 start), confirmation/undo affordances for
  irreversible ones (`transfer_ownership`, `bump_epoch`), and whether
  on-chain grant vs off-chain blob is the UI default.
- **Tailscale ACLs vs wallet auth overlap.** How much to lean on tailnet
  ACLs as a coarse pre-filter vs. treating the wallet as the only real
  gate.
