# Browser web-attach (proposal)

> **Status: design proposal.** Nothing here is implemented yet. This
> document designs a [ttyd](https://github.com/tsl0922/ttyd)-equivalent:
> attach to a running `mosey launch` from a web browser, with the
> browser wallet handling authentication when the session was launched
> with [wallet support](wallet-auth.md). It reuses the existing
> [WebSocket transport](transports.md#websocket-backend), the
> [TypeScript client](../../clients/typescript/), the wallet handshake,
> and the inline `signMessage` flow — and adds one new component: a
> **personal, wallet-bound libp2p agent**.
>
> An earlier draft of this proposal put a full libp2p node *in the
> browser* and leaned on transparent relays; it hit a series of walls
> (browsers can't dial TCP/QUIC, can't be a DCUtR endpoint, and
> go-libp2p has no relay-signalled WebRTC listener). This revision
> moves the libp2p node *out* of the browser into a per-user agent,
> which removes those walls entirely. The superseded analysis is
> preserved in git history (`docs(web-attach): add browser web-attach
> design proposal`).

## The one idea

A browser can't reach a NAT'd `mosey` host directly, and browsers are
*bad libp2p nodes*: they can't dial TCP/QUIC, can't hole-punch, and
can't be the listening end of relay-signalled WebRTC against a go-libp2p
host. Rather than fight that, **don't make the browser a p2p node at
all.**

Instead, put a **personal libp2p node between the browser and the
network** — an *agent* the user runs, **bound to their wallet**. The
browser is a thin, static web terminal that drives its agent over a
WebSocket; the agent does all the libp2p (discovery, NAT traversal,
hole-punching) and runs the mosey wallet handshake against hosts on the
user's behalf. The browser never speaks libp2p.

```
   static web terminal (GitHub Pages)        your agent (a node you run)         a mosey host
   ┌───────────────────────────┐    WSS     ┌────────────────────────────┐      ┌──────────────┐
   │ • wallet connect (Phantom) │◀─────────▶│ • full libp2p node          │      │ launch       │
   │ • xterm.js                 │  (drives   │ • wallet-LOCKED ingress (W) │ libp2p│ peer_id ==   │
   │ • points at YOUR agent     │   agent)   │ • holds W→K_agent delegation│◀────▶│  session_key │
   │ • no libp2p, stateless     │            │ • DHT resolve + hole-punch  │ + DCUtR└──────┬──────┘
   └───────────────────────────┘            └────────────────────────────┘             │ (if NAT'd)
                                                                                         ▼
                                                                              ┌───────────────────┐
                                                                              │ host's NAT relay   │
                                                                              │ (mediation only;   │
                                                                              │  sees ciphertext)  │
                                                                              └───────────────────┘
```

The two tricky hops both land on the **right** side of the browser's
limitations:

- **browser ↔ agent** is plain **WSS** — the one thing every browser
  does well.
- **agent ↔ host** is **full-node ↔ full-node libp2p** — so DHT
  discovery, circuit-relay-v2, and **DCUtR hole-punching all work**.
  The browser's inability to hole-punch is irrelevant; its agent does it.

## What this buys (and what it costs)

| | Browser as a full p2p node (superseded) | **Browser drives a personal agent (this proposal)** |
|---|---|---|
| Browser | js-libp2p node (WSS/WebRTC/circuit) | thin static WSS terminal, **no libp2p** |
| Reaching a NAT'd host | relay-signalled WebRTC (**unsupported by go-libp2p**) or stuck always-relayed | **DHT + host's relay + DCUtR → direct** |
| Hole-punch | impossible (browser can't) | **works** (agent is a full node) |
| Key material in browser | non-extractable `K_c` + IndexedDB cache | **none** — lives at the agent |
| Infra the user runs | maybe none | **a personal agent node** (the real cost) |
| Trust | relays see only ciphertext | the agent (yours) is an endpoint — **sees your plaintext** |

The cost is real and worth stating plainly: each user runs an always-on
agent, and that agent is a *trusted endpoint* for their own sessions (it
terminates the secure channel, so it sees the PTY plaintext and holds a
session-access delegation). That is acceptable precisely because **it is
your own, wallet-locked node** — but it is the defining trade of this
design. A future fallback could let the static page run as a full
js-libp2p node for users unwilling to run an agent (see
[Open questions](#open-questions)).

## What already exists (and is reused)

| Piece | Status | Role here |
|---|---|---|
| WebSocket transport + TS `MoseyClient` | done | the **browser ↔ agent** link reuses it verbatim — the agent serves `/mosey/{auth,pty,control}` to the browser over WSS, exactly what `MoseyClient` + [`xterm-demo.html`](../../clients/typescript/examples/xterm-demo.html) already speak |
| Wallet handshake (server + client) | done | the **agent ↔ host** auth; the agent is the mosey client, the host is unchanged |
| Canonical delegation, `signMessage` flow | done | `W → K_agent` delegation; browser→agent login proof |
| [`walletsolana`](../../walletsolana/) snapshot | done | reused by the agent for chain reads (dashboard, host's relay pointer) |

The host side does not change at all: a host is already a libp2p node
whose `peer_id == session_key`, authenticating attachers with the
existing wallet handshake. The agent is just another attacher.

## The static web terminal

Generic, deploy-once (GitHub Pages or anywhere), and **drops js-libp2p
entirely**. It is essentially today's `xterm-demo.html` plus wallet
login:

- **wallet connect** (Phantom / Solflare / Backpack),
- **WSS to your agent**, authenticated as `W` (below),
- a **session dashboard** (the chain read — see [Discovery](#discovery)),
- **xterm.js**, driven over the WSS link with the existing `MoseyClient`.

It is **stateless**: no connection key, no delegation cache, no IndexedDB
— those all live at the agent. The page holds nothing but the current
WSS session.

### Pointing the page at your agent

The page learns its agent's address by one of, in increasing
zero-config:

1. **URL fragment** — `#agent=wss://my-agent.example/...`; bookmark it.
2. **localStorage, per wallet** — entered once, remembered for that wallet.
3. **On-chain `wallet → agent` record** (optional) — connect `W`, look up
   `W`'s agent address. "Bound to the wallet" in the strongest sense; the
   agent address is stable infra, so it sits fine on-chain (small
   metadata leak — opt-in).

Pointing a **public** page at your agent is safe: the agent is
**wallet-locked**, so a visitor whose wallet isn't `W` is rejected at the
ingress handshake regardless of knowing the address.

## The personal agent

A full libp2p node the user runs (a cloud box, or home + dyndns), with a
**WSS listener carrying a TLS cert** so the browser can reach it. It is
the wallet-locked relay this proposal kept circling back to — now the
core component rather than an optional one.

- **Wallet-locked ingress.** On a new browser connection the agent runs a
  challenge/response: the browser proves control of wallet `W` via a
  per-login `signMessage` (see [Open questions](#open-questions) for the
  no-prompt variant). A non-`W` wallet is dropped before anything else —
  no session is reachable through someone else's agent.
- **Holds `W`'s delegation.** Once, the user signs `W → K_agent`
  (delegating to the agent's libp2p key). Thereafter the agent runs the
  mosey wallet handshake with hosts as an authorized client, with no
  further wallet prompts.
- **Reaches hosts as a full node.** It resolves a chosen session via the
  DHT, dials the host (directly, or through the host's NAT relay), and
  **DCUtR-upgrades to a direct connection** — then bridges the PTY /
  control / auth streams to the browser over WSS.

It never serves anyone but `W`, so "lock my relay to my wallet" falls out
of the ingress check; there is no separate ACL to design.

## Discovery

Two layers, and the agent — not the browser — does the hard one.

- **Which sessions (the menu).** A `getProgramAccounts` read keyed by the
  connected wallet lists its sessions: owned
  (`memcmp(owner, W)`) and granted (`Grant.grantee == W`). The browser
  can do this directly (just needs `W`'s pubkey) or ask the agent. It
  reuses the Solana RPC the project already depends on — no new
  third-party dependency, and for chain sessions it is the directory of
  *which*.
- **Where the host is (the address).** The **agent** resolves it with
  full libp2p: `FindPeer(session_key)` over the DHT, plus the host's
  optional **on-chain `relay` pointer** telling it which NAT relay to
  route through. The browser resolves nothing.

The host's `relay` pointer is a small **program change** (an optional
`relay` field on the `Session` account, set at `register` / a new
`set_relay`). It is legitimate on-chain data because a *relay* is stable
infra — unlike the host's address, which churns and stays off-chain. So
the boundary is: **chain = who owns · who may attach · which relay;
off-chain = the host's current address** (resolved by the agent).

## Hosts and NAT

A host needs **no inbound reachability and no browser-facing transport**
— a sharp simplification over the superseded design:

- **Directly reachable host** → the agent dials it directly.
- **NAT'd host** → it reserves on **its own relay** (AutoRelay /
  circuit-relay-v2), purely for NAT mediation. The agent reaches it
  through that relay and then **hole-punches to a direct connection**, so
  the relay drops out of the data path. Because the agent↔host channel is
  end-to-end Noise, that NAT relay only ever sees **ciphertext** — it can
  be shared or public; access is gated end-to-end by the host.

Crucially there is **no 1:1 relay relationship**: the host's NAT relay
and the user's agent are different nodes that meet via the DHT. A
grantee's agent reaches your host through *your host's* relay, not
through your agent.

## Wallet auth, end to end

- **browser → agent:** prove control of `W` (per-login `signMessage`).
  This is *login to your own agent*, not session access.
- **agent → host:** the existing mosey wallet handshake, unchanged on the
  host side. The agent presents the `W → K_agent` delegation (plus any
  chain the grant requires); the host folds it against its
  [on-chain snapshot](wallet-auth.md#snapshot-and-freshness) → `Identity`
  → caps. Replay binding holds: the delegation names `K_agent`, and the
  handshake binds `K_agent` to the agent↔host connection.
- **caps are enforced at the host**, from the snapshot ∩ the presented
  chain, regardless of what the agent or browser requests.

## Grantees

Each participant runs **their own** wallet-bound agent. A grantee
connects their wallet → their agent → which attaches to the owner's
session: the agent holds the grantee's delegation (or relies on the
grantee's on-chain grant), finds the host via the DHT and the host's NAT
relay, and hole-punches in. **No shared relay, no 1:1 binding, and a
grantee never touches the owner's agent.** This is the topology the
relay-coupling discussion kept pointing at; the agent model delivers it.

## Security

- **The agent is a trusted, sensitive node.** It terminates the secure
  channel (sees your PTY plaintext) and holds `W`'s session-access
  delegation. It is *yours*, so that is acceptable — but treat it like
  any credentialed agent: **scope the delegation** (short `not-after`,
  refreshed; least caps), sandbox the process, and keep the wallet-locked
  ingress on.
- **The host's NAT relay sees only ciphertext** (agent↔host Noise is
  end-to-end), so it can be untrusted / shared.
- **Session authenticity is transport-proven.** `peer_id == session_key`;
  Noise proves the agent reached the real session.
- **The static page is a fixed public bundle** holding no secrets; it is
  safe to point at a wallet-locked agent because non-`W` is rejected.
- **TLS** is mandatory on the agent's WSS listener (browser requirement).

## Where it plugs into the code

- `cmd/mosey/agent.go` (**new**) — the personal agent: a full libp2p node
  with a wallet-locked WSS ingress (challenge/response on `W`), a held
  `W → K_agent` delegation, DHT/`relay`-pointer resolution, host dial +
  DCUtR, and a bridge from the host's `/mosey/{auth,pty,control}` streams
  to the browser's WSS. Reuses [`walletsolana`](../../walletsolana/) for
  chain reads.
- `webui/` (**new**) — the static thin terminal: wallet connect + ingress
  login + dashboard + xterm over the existing `MoseyClient` WSS path. No
  libp2p, no key storage. An esbuild bundle; deploy to GitHub Pages.
- [`programs/mosey-session`](../../programs/) — optional `relay` field on
  `Session` (set at `register_session` / a new owner-only `set_relay`);
  optional `wallet → agent` record for zero-config pointing.
- [`walletsolana`](../../walletsolana/) — owner/grantee-indexed
  `getProgramAccounts` for the dashboard; decode the new `relay` field.
- [`transport/libp2p`](../../transport/libp2p/) — host side: ensure the
  host is DHT-discoverable and (if NAT'd) reserves on its relay; surface
  the dial info. (Largely already present via AutoRelay.)
- [`clients/typescript`](../../clients/typescript/) — the browser↔agent
  link reuses `MoseyClient`'s WebSocket transport as-is; new code is only
  the wallet-connect + agent-login glue and the dashboard.
- Docs — this file; a `mosey agent` entry in [the CLI surface](cli.md).

Note what this design **drops** versus the superseded one: js-libp2p in
the browser, browser-side `K_c` + IndexedDB, and all the
WebRTC/transparent-relay machinery.

## Phasing

```
P0  ── Agent + thin terminal against a reachable host ────────────────
      mosey agent: wallet-locked WSS ingress → bridge to a directly
        reachable host over libp2p
      static terminal: wallet login + xterm over MoseyClient (WSS)
      ✦ open the page → log in with your wallet → a terminal

P1  ── NAT traversal ─────────────────────────────────────────────────
      agent: DHT FindPeer + reach a NAT'd host via its relay + DCUtR
      host: reserve on its NAT relay (mediation only)
      ✦ reach a host with zero inbound reachability — direct after holepunch

P2  ── Chain-driven discovery ────────────────────────────────────────
      Session.relay pointer (program change); wallet dashboard
      optional on-chain wallet→agent record; relay-pointer routing
      ✦ connect wallet → pick a terminal, zero manual addressing

P3  ── Multi-party + ergonomics ──────────────────────────────────────
      grantee flows end to end; delegation scope/refresh at the agent
      optional Model-1 (browser-as-full-node) fallback for agent-less viewers
```

P0 needs no NAT traversal and no chain — just the agent bridging to a
reachable host, with the browser reusing the existing WSS client. Each
later phase is additive.

## Open questions

- **browser → agent login.** Per-login wallet `signMessage` (chosen for
  P0 — simplest) vs. a stored `W → K_browser` delegation that avoids a
  prompt on every login (browser regains a little state). Revisit if the
  per-login prompt grates.
- **Pointing the page at the agent.** URL fragment / localStorage /
  on-chain `wallet → agent` record — which to default to, and whether to
  add the on-chain record at all (it leaks the agent's location).
- **Agent delegation scope.** Caps + `not-after` for `W → K_agent`, and
  the refresh cadence — the agent is a standing credential, so this is the
  main blast-radius control.
- **Agent-less viewers.** A casual one-off viewer may not want to run an
  agent. Options: a Model-1 (browser-as-full-node) fallback path in the
  same static page, or a shared/trusted agent. Deferred; both are real
  work.
- **Agent vs host-relay overlap.** Whether one node can serve both roles
  in small deployments, or they stay separate by default.
