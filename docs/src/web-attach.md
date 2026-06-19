# Browser web-attach (proposal)

> **Status: design proposal.** Nothing here is implemented yet. This
> document designs a [ttyd](https://github.com/tsl0922/ttyd)-equivalent:
> attach to a running `mosey launch` from a web browser, with on-chain
> [wallet auth](wallet-auth.md) deciding what you may attach to. It is a
> **self-hosted web gateway**: a small service you run that is a full
> libp2p node *and* a web terminal, reached from your browser over a VPN
> (Tailscale).
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

## The browser side

A normal web client — **no libp2p, no key storage:**

- loads the UI from the gateway over Tailscale HTTPS,
- **wallet connect** (Phantom / Solflare / Backpack) for authorization,
- a **session dashboard** (the chain read — see [Discovery](#discovery)),
- `xterm.js`, driven over a WebSocket to the gateway with the existing
  `MoseyClient`.

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

This is also what makes the gateway naturally **single- or multi-user**:
whoever logs in supplies their own delegation, and the gateway attaches
with *their* on-chain access. A personal gateway just has one user.

## Discovery

- **Which sessions (the menu).** `getProgramAccounts` keyed by the
  connected wallet — owned (`memcmp(owner, W)`) and granted
  (`Grant.grantee == W`). The browser or the gateway runs it; it reuses
  the Solana RPC the project already depends on.
- **Where the host is.** The **gateway** resolves it like any libp2p
  node: a tailnet/LAN address directly, or `FindPeer(session_key)` over
  the DHT (optionally hinted by the host's on-chain `relay` pointer for a
  NAT'd host). The browser resolves nothing.

The host's on-chain `relay` pointer (an optional `Session` field — a
small program change) matters only for NAT'd-elsewhere hosts that use a
specific relay; hosts on your tailnet or on the public swarm don't need
it. The boundary remains: **chain = who owns · who may attach · (which
relay); off-chain = the host's current address.**

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
  the browser. Mints `K` per login and runs the host handshake with the
  browser-supplied `W → K`.
- `webui/` (**new**) — the web UI (xterm + wallet connect + dashboard),
  served by `mosey web`. Browser↔gateway reuses `MoseyClient`'s WebSocket
  transport as-is; new code is only wallet-login + dashboard glue.
- [`clients/typescript`](../../clients/typescript/) — the
  browser-side login/dashboard glue; the transport layer is unchanged.
- [`walletsolana`](../../walletsolana/) — owner/grantee-indexed
  `getProgramAccounts` for the dashboard.
- [`programs/mosey-session`](../../programs/) — *optional* `relay` field
  on `Session` (only for NAT'd-elsewhere hosts pinned to a relay).
- **Deployment** — a `Dockerfile` for `mosey web` and a short runbook for
  `tailscale serve` (HTTPS + MagicDNS); `Headscale` noted for a
  no-third-party tailnet.

What this design **drops** versus the superseded drafts: js-libp2p in the
browser, browser-side `K_c` + IndexedDB, all WebRTC/transparent-relay
machinery, and any user-maintained relays.

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

P2  ── Chain-driven discovery ────────────────────────────────────────
      wallet dashboard (which sessions); optional Session.relay pointer
      ✦ connect wallet → pick a terminal

P3  ── Multi-party + ergonomics ──────────────────────────────────────
      grantee flows; multi-user gateway; reconnect / pty-resume in the UI
```

P0 is small — it is `mosey attach` to a reachable host with a web
front-end, behind your VPN. Everything after is additive.

## Open questions

- **Single- vs multi-user gateway.** Personal (one wallet) is the default;
  multi-user falls out of per-login `W → K`, but session isolation and
  resource limits in a shared gateway need design.
- **`W → K` scope + refresh.** Caps and `not-after`, and whether a long
  session silently re-prompts the wallet on expiry.
- **VPN choice.** Tailscale is the assumed default (`tailscale serve` for
  HTTPS); document Headscale for self-hosting the control plane, and the
  generic "any reverse-proxy/VPN that fronts the gateway" path.
- **Is `Session.relay` worth keeping?** Tailnet + public swarm cover most
  hosts; the on-chain relay pointer may not earn its program change.
- **Agent-less is already true here** — but the old "open to any browser
  with your wallet" reach is what we gave up; revisit if a
  no-VPN/public-gateway tier is ever wanted (it reintroduces the public
  exposure this design removed).
