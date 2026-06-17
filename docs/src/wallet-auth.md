# Wallet authentication (proposal)

> **Status: draft proposal.** Nothing here is implemented. This
> document designs a third authenticator — a wallet/blockchain
> credential — alongside [PSK and cert auth](auth.md). It commits to
> the *hybrid* model (on-chain root of trust, off-chain delegation)
> and records the chain-selection analysis, including Nano.

## The one idea

mosey's [cert auth](auth.md) is already a centralized version of
what a wallet credential would do. Read that page first; this
proposal only swaps out the **root of trust** and the **delegation
mechanism**, and reuses everything else.

| Concept | Cert auth today | Wallet auth |
|---|---|---|
| Root of trust | workspace master Ed25519 key | a wallet that controls the session on-chain |
| Identity | the agent's `peer_pubkey` | the wallet's public key / address |
| Capability grant | master-signed cert (`api/cert.proto`) | on-chain ownership **or** an owner-signed delegation |
| Forging a viewer | `mosey cert mint-agent` | owner signs an off-chain delegation (no transaction) |
| Revocation | serial in revocation file | transfer/burn the token, or short-lived delegations |

The capability bits (`Owner`, `Write`, `Resize`) and every layer
that authorizes against them — `vterm/control.go`, the PTY input
pump, the [multi-client modes](multi-client.md) — are untouched.
Wallet auth is purely a new way to *populate an `Identity`*.

## The chain is not the data path

The single most important constraint: **session bytes never touch
the chain, and the hot path never makes an RPC call.** The chain is
a slow-changing registry of *who owns what*. The mosey server reads
it once (and on change), caches a snapshot, and authorizes against
the snapshot. A `launch` with no network path to a chain node must
still be able to accept connections from a cached snapshot.

This is also why "free transactions" turns out to be a near
non-issue: the thing you do constantly — handing someone view
access — is an **off-chain signature**, not a transaction. Only
*ownership* and *revocation* ever hit the chain, and rarely.

## Three layers

```
Layer 1  ON-CHAIN  (rare: ownership, revocation)
   registry:  sessionId ──owns──▶ ownerWallet
   the only thing that must be globally agreed.

        │ owner signs — NO transaction, feeless, offline
        ▼
Layer 2  OFF-CHAIN DELEGATION  (frequent: grants)
   Delegation{ sessionId, delegate, caps,
               canForge, notBefore, notAfter, nonce }
   signed by the owner (or an upstream delegate).
   caps ⊆ delegator.caps   ← attenuation, enforced on verify.

        │ presented at attach
        ▼
Layer 3  RUNTIME HANDSHAKE  (every connect)
   wallet proves control by signing the server nonce;
   server folds the delegation chain → Capabilities →
   the same auth.Identity every other authenticator emits.
```

### Layer 2: forging is delegation, and it's free

"An owner can forge a viewer token; a viewer cannot forge anything"
is the [capability-attenuation](https://en.wikipedia.org/wiki/Capability-based_security)
rule you find in macaroons, SPKI, and
[UCAN](https://ucan.xyz) — worth reading those as prior art, this
is not a novel scheme.

- A delegation may grant only a **subset** of the signer's caps.
- The owner holds a `canForge` capability; the delegation it signs
  to a viewer **omits** `canForge`.
- If the viewer signs a downstream delegation, the server rejects
  it: the child claims caps the parent lacked. No `canForge` in the
  chain → no valid children.

Each grant is one signed struct. No gas, no transaction, no chain
round-trip — works offline, revoked by a short `notAfter`. This is
the direct analogue of `mosey cert mint-agent`, except the signer
is a wallet instead of the master key, and there's no CLI ceremony.

The same attenuation can instead be **minted on-chain** (a grant
record keyed to the grantee's wallet, gated by the program's
`canForge` check) when you'd rather pay a transaction to skip
transmitting a credential entirely. Both are "Layer 2"; they differ
only in *where the grant lives* and *how it reaches the grantee* —
see [Forging a viewer grant](#forging-a-viewer-grant).

### Layer 3: the handshake

Mirror `auth/cert.go`'s symmetric nonce challenge:

```
client ─ WalletHello{ wallet, delegationChain[], nonce_c } ─▶ server
client ◀──────────────── nonce_s ──────────────────────────── server
client ─ sig = sign_wallet( nonce_s ‖ peerPubKey ‖ sessionId ) ▶ server
                                                          server:
   recover/verify sig == wallet            (proves wallet control)
   walk delegationChain to an on-chain owner of sessionId
   caps = fold(chain)  (each hop ⊆ parent; root ⊆ on-chain caps)
   emit Identity{ Label: wallet, Caps }
```

Two things to steal from the cert design:

1. **Bind the signature to the transport key.** The cert binds
   `peer_pubkey`; the wallet must too. Signing over
   `nonce_s ‖ peerPubKey ‖ sessionId` stops a captured signature
   from being lifted onto another connection. Without this, the
   wallet sig is a bearer token an eavesdropper can replay.
2. **Reuse the correlation plumbing.** `auth.Wrap` already matches
   the auth stream to the PTY/control stream via `RemoteID()` (see
   the backend table in [auth.md](auth.md)). Wallet auth changes
   none of it.

## Session identity and resurrection

On-chain ownership needs a *stable* thing to own. mosey sessions are
ID-less today — you dial an endpoint, not an identifier — so this
proposal introduces a **persistent session keypair**.

It is *not* the libp2p peer id, despite the temptation. The libp2p
backend already generates an Ed25519 host key and the peer id is its
multihash (`transport/libp2p/libp2p.go`), but:

- The key is **ephemeral** unless persisted — a crash/restart yields
  a new peer id (the code comment even flags this: *"persist when
  you need a stable peer id across restarts"*).
- The peer id **only exists on the libp2p backend.** ws/http2/unix
  have no equivalent (see the correlation table in [auth.md](auth.md)).

So the terminal's identity must be its own persisted, transport-
independent Ed25519 keypair — and then *reused* as the libp2p host
key so discovery comes along for free:

```
~/.mosey/sessions/<name>.key   ← Ed25519, persisted, the root of identity
        │
        ├─ pubkey = the canonical session/terminal ID
        ├─ fed to libp2p Options.Identity → stable peer id → DHT rediscovery
        └─ registered on-chain: registry[ sessionPubkey ] = ownerWallet
```

**Resurrection falls out of this.** The on-chain ownership record
outlives the process, so reviving a dead terminal is just
*"relaunch with the same key file"*: same session ID, same peer id,
same on-chain owner, and every outstanding [Layer-2 delegation](#three-layers)
stays valid because it references the session ID, not the connection.

How a dialer finds a moved/restarted terminal is the transport's job,
and the peer-id authentication described above is exactly the right
mechanism: an address is *where*, the peer id is *who* (proven by the
Noise handshake, not assumed), and the DHT resolves a bare peer id to
its current addresses. Persisting the key turns "find the terminal
again after it moved" into a stock libp2p capability.

## Chain selection

The hybrid model needs the chain to do exactly two things:

1. Hold a mapping `sessionId → ownerWallet` that anyone can read.
2. Let ownership change (transfer) and let access be revoked.

Everything richer (caps, forging, expiry, multi-hop delegation)
lives off-chain in Layer 2. So the chain question reduces to: *can
it host a small, mutable, publicly-readable ownership pointer,
feelessly?*

### Nano

Nano is attractive on the surface — feeless by design, and its
accounts are **Ed25519 keypairs**, the same primitive mosey already
uses everywhere (no secp256k1 / `ecrecover` path to add). If we
were only after "a feeless source of Ed25519 identities," it's a
clean fit.

The problem is Layer 1. Nano is a purpose-built *currency*, not a
programmable ledger:

- **No smart contracts.** You cannot deploy a registry, an NFT, a
  soul-bound token, or any `canForge` minting logic. There is no
  place to *put* `sessionId → owner`.
- **No data/memo field.** A standard Nano block carries an account,
  a balance, a previous-block hash, and a representative — nowhere
  to attach a sessionId or a capability commitment. (You *can* abuse
  the 128-bit `amount` field to smuggle ~16 bytes; that's a hack,
  not a foundation.)
- **Accounts must be opened** by first receiving a send, so even a
  "feeless" scheme needs a dust faucet and some funded account to
  bootstrap each session identity.

So Nano sits in the awkward middle: it's enough infrastructure to
pay the integration cost of "talk to a chain," but not programmable
enough to actually host the ownership registry the hybrid model
needs.

There is *one* genuinely clean trick if you want to use Nano anyway.
Every Nano account has a mutable, on-chain, feeless **representative**
field (normally used for consensus voting). Repurpose it as the
ownership pointer:

- A session is a dedicated Nano account `S`.
- `representative(S) == O` *means* "wallet `O` owns session `S`."
- Transferring ownership = `S` publishes a block changing its
  representative to `O'`. Feeless, on-chain, uses only standard
  fields, no `amount` abuse.
- The mosey server is configured with `S`'s **public** key; it
  queries a node for `account_representative(S)` and trusts
  delegations rooted at `O`.

The catch: only the holder of `S`'s **private key** can change its
representative, so the true root authority is "whoever holds `S`'s
key," and the representative is just a redirect to the *delegation*
root. It works, but it's a creative repurposing — expect to
document it heavily and to own the edge cases (account not yet
opened, representative pointing at a dead account).

**Verdict:** Nano is a poor fit for a programmable capability
registry, and its one advantage (feeless) is already delivered by
off-chain delegation (also feeless). Pick it only if feeless Ed25519
identities plus the representative-pointer trick are genuinely worth
more to you than a registry contract — and accept that you're
bending a payments network into a role it wasn't built for.

### Recommendation: Solana

Use **Solana**. The deciding factor is concrete and specific to this
codebase: it is **Ed25519 end-to-end, and so is mosey.**

- mosey is Ed25519 throughout (cert auth, libp2p host key), the
  [session keypair](#session-identity-and-resurrection) is Ed25519,
  and **Solana wallets are Ed25519.** So the Layer-2 delegation
  signatures are verified by mosey's *existing* Ed25519 code. An EVM
  chain would force a whole secp256k1 + keccak + `ecrecover` path
  onto the wallet side for no other benefit.
- One key type spans three roles: the session ID, the on-chain
  account authority, and the wallet.
- The on-chain record is a **PDA derived from the session pubkey**,
  so a restarted terminal re-derives the same on-chain address — the
  resurrection story and the registry agree by construction.
- Fast finality, single global state (no L2 fragmentation), a solid
  Go SDK (`gagliardetto/solana-go`) for the snapshot refresher, and
  `@solana/web3.js` for client signing.

**Honest cost.** Solana is not *literally* free: ~5000 lamports base
fee per signature plus a small **refundable** rent-exempt deposit
(~0.002 SOL) per session record, so the session creator needs a
dust-funded keypair. But the hybrid model already pushed the
*frequent* operation — granting view access — off-chain, where it's
genuinely free. On-chain writes are rare (create / transfer / revoke),
so the residual cost is dust on infrequent ops, not per-attach.

For **non-critical use cases, point at Solana devnet** and the
experience is actually free — devnet SOL comes from a faucet, so
create/transfer/revoke cost nothing real. Mainnet-beta is there when a
session's ownership is worth anchoring to a chain people trust. Same
program, same code path; only the RPC endpoint and the funding source
change.

Cost of admission: a small **Anchor (Rust) program** — a PDA per
session holding `owner: Pubkey` plus `create / transfer / revoke`
instructions that emit events the server subscribes to for snapshot
refresh.

### The alternatives, ranked for this use case

| Option | Layer-1 fit | "Free" story | Notes |
|---|---|---|---|
| **Solana** (recommended) | Full — PDA registry, on-chain `canForge` | Devnet free; mainnet dust + refundable rent | **Ed25519 reuses mosey's crypto.** Anchor program in Rust. |
| **Gasless EVM L2 (relayer)** | Full — registry contract, NFT/SBT | Users sign, relayer pays → feels free | Richest tooling; adds the secp256k1/`ecrecover` path. |
| **Near-free EVM L2** (Gnosis, Polygon) | Full | Sub-cent, not literally zero | Simplest "real chain"; still secp256k1. |
| **Near** | Full (different VM) | Native meta-tx → truly gasless UX; Ed25519 | Weaker Go SDK story than Solana/EVM. |
| **App-specific / L3 / testnet** | Full | Effectively free writes | Weaker external security — fine here, since *no money is involved*. |
| **Nano** | **Poor** — no contracts, no data field | Feeless | Only the representative-pointer hack; see above. |
| **No chain at all** | n/a | free | This is just today's [cert auth](auth.md). If you don't need decentralized/transferable ownership, you may not need a chain. |

Because the brief is "no money involved," the security budget is
*"nobody can forge access,"* not *"nobody can steal funds"* — which is
exactly why devnet, or even an app-specific chain, is adequate for the
non-critical tier, and why the Ed25519 fit outweighs raw fee
comparisons.

## Soul-bound vs. transferable

Decide it **per role**, not globally:

| Role | Recommendation | Why |
|---|---|---|
| **Owner** | Transferable `owner` field | A `transfer_ownership` instruction hands off the whole session (rotate ownership, hand off a project). Plain `Session.owner` field — an SPL/Metaplex NFT is a later opt-in if wallet-display or trading ever matters. |
| **Viewer / collaborator** | Off-chain delegation, address-bound (or soul-bound SBT) | Bound to one recipient wallet so access can't be resold or forwarded. Prefer the free off-chain delegation with a short expiry; mint an actual SBT only if you want the grant publicly auditable. |

A soul-bound viewer grant and an address-bound off-chain delegation
express the same intent ("this access belongs to *this* wallet");
the SBT just pays gas to make it visible on-chain. Default to the
delegation.

## On-chain program (Anchor)

A deliberately small program: it records ownership and owner-issued
grants and emits events the server's snapshot cache follows. It never
sees agent keys, transport keys, or session bytes — only wallets.

### Accounts

```rust
#[account]
pub struct Session {
    pub session_key: Pubkey, // persisted Ed25519 session id; PDA seed
    pub owner:       Pubkey,
    pub epoch:       u16,    // bump to mass-revoke
    pub bump:        u8,
}
// PDA: [b"session", session_key]

#[account]
pub struct Grant {
    pub session: Pubkey,     // the Session PDA
    pub grantee: Pubkey,     // a wallet — never an agent key
    pub caps:    u8,         // WRITE | RESIZE | FORGE
    pub expiry:  i64,        // 0 = none
    pub epoch:   u16,        // session.epoch stamped at mint
    pub bump:    u8,
}
// PDA: [b"grant", session, grantee]
```

Capability bits mirror `auth.Capabilities`:

| bit | value | meaning |
|---|---|---|
| `WRITE`  | 1 | keystrokes to the PTY |
| `RESIZE` | 2 | resize the PTY |
| `FORGE`  | 4 | may sign **off-chain** delegations rooted at this grant |

`OWNER` is not a grant bit — it is the `Session.owner` field, and the
owner implicitly holds `WRITE | RESIZE | FORGE`.

### Instructions

```rust
register_session(session_key)  // signers: owner (payer) + session_key
transfer_ownership(new_owner)  // signer:  owner
grant(grantee, caps, expiry)   // signer:  owner; caps ⊆ {WRITE,RESIZE,FORGE}
revoke(grantee)                // signer:  owner; closes Grant PDA, rent → owner
bump_epoch()                   // signer:  owner; epoch += 1
```

Two choices worth stating outright:

- **Minting is owner-only**, so the program needs no `granter`
  pointer and no cascade logic — `grant` / `revoke` are owner-signed,
  full stop. Deep, multi-level delegation still exists, but on the
  **free off-chain path**: a grant carrying `FORGE` authorizes its
  holder to sign off-chain delegation chains (checked against the
  snapshot). On-chain stays flat and cheap; off-chain stays
  arbitrarily deep and free.
- **`register_session` is co-signed by the session keypair**, proving
  the registrant controls that terminal identity. Without it, anyone
  could squat a `session_key` they don't own.

### What the server computes

The snapshot resolver treats an on-chain grant as **live** iff:

```
exists Grant[session, wallet]
  && grant.epoch == session.epoch          // not swept by bump_epoch
  && (grant.expiry == 0 || grant.expiry > now)
```

Live caps for a wallet = the grant's `caps`, unioned with any valid
off-chain delegations rooted at that wallet; the owner always resolves
to `WRITE | RESIZE | FORGE`. `bump_epoch` invalidates every prior
grant in one transaction; re-enabling someone is a fresh `grant` that
stamps the current epoch.

### Discovery stays off-chain

The program stores **no endpoint**. `session_key` doubles as the
libp2p peer id, so a dialer resolves peer-id → current address via the
DHT — resurrection and address churn cost zero transactions and
publish nothing. The chain answers *who may attach*; the DHT answers
*where*. See [Session identity and resurrection](#session-identity-and-resurrection).

### Events

`SessionRegistered`, `OwnershipTransferred`, `GrantMinted`,
`GrantRevoked`, `EpochBumped` — they drive the snapshot refresh (see
[Snapshot and freshness](#snapshot-and-freshness)).

### Deployment & governance

There is **one canonical reference program at a constant program id**,
baked into mosey — so a viewer needs only the session id, never which
program a session lives in. Operators who want to self-govern (or
fork) deploy their own instance and point at it with `--program <id>`;
the session id and `--program` together name a session unambiguously.

Upgrade authority is a backdoor into auth — whoever holds it can
rewrite ownership and grant logic the server trusts. So the canonical
program's authority is **phased toward immutable**:

1. **devnet** — a single upgrade key, to iterate freely.
2. **mainnet bring-up** — a Squads M-of-N multisig.
3. **stable** — **burned to immutable** (`--final`).

The program is small and freezable, and immutability is the strongest
trust story for an auth primitive. A genuine bug after burning is
handled by deploying a v2 program and letting sessions re-register
under it — and the `--program` override means anyone can fork and run
a patched instance meanwhile. Self-deployers choose their own posture.

## Snapshot and freshness

The handshake must never block on an RPC call, so the server
authorizes against an in-memory **snapshot** of this session's
on-chain state, refreshed in the background. A `launch` hosts exactly
one session, so the snapshot is small and bounded: one `Session`
account plus its `Grant` PDAs, fetched in a single
`getProgramAccounts(program, memcmp(session))`.

### Refresh is asymmetric on purpose

The two staleness directions carry different risk, so they get
different mechanisms:

- **Revocation must propagate fast** — honoring a revoked grant is the
  only real security risk, and only on a *new* handshake (live
  connections are untouched; cutting one is `mosey control kick`).
- **New grants can arrive lazily** — a not-yet-known grant only delays
  a viewer, with no security impact.

So:

| Change | Mechanism | Latency |
|---|---|---|
| `transfer_ownership`, `bump_epoch` | `accountSubscribe` on the Session PDA | ~one slot |
| `revoke` / close of a known grant | `accountSubscribe` on each known Grant PDA | ~one slot |
| a **new** `grant` | `getProgramAccounts` backstop poll (or on-demand verify) | poll interval |

The poll also heals missed WS notifications and detects a dead socket.
Reads and subscriptions run at **`confirmed`** commitment (`finalized`
is a high-assurance knob); `processed` is never used — a grant a reorg
could roll back must not have been honored.

### Liveness and posture

A wallet's caps come from the resolver predicate in
[What the server computes](#what-the-server-computes), unioned with any
valid off-chain delegations. Two policies govern the edges:

- **Outage → fail-open within a budget.** While the RPC/subscription
  is unreachable the server keeps serving the last-known snapshot up
  to `maxStaleness` (default ~30s), then **fails closed** — refusing
  new handshakes until a refresh succeeds. Availability by default,
  with a bounded window in which a just-revoked grant could still be
  honored *on a new connection*; grant `expiry` is the backstop and
  live sessions are never affected. Tune `maxStaleness` toward 0 for
  security-sensitive deployments, or lift the ceiling for maximum
  availability.
- **Cache miss → on-demand verify.** When a validly-signed wallet
  isn't in the snapshot, the server does **one** blocking
  `getAccountInfo` on the expected Grant PDA (short timeout,
  rate-limited per peer) before rejecting. It admits a freshly-granted
  viewer immediately instead of making them wait a poll interval, and
  can only ever *admit* a wallet that holds a real on-chain grant — so
  it never weakens security, it only erases stale-negative latency.
  Verifying the wallet signature *before* the lookup, plus the rate
  limit, bounds the hot-path RPC a peer can induce.

### Lifecycle

- **Warm start.** The snapshot is persisted to the `--snapshot` path;
  on (re)launch the server loads it instantly and refreshes in the
  background, so a [resurrected terminal](#session-identity-and-resurrection)
  authorizes immediately rather than blocking on a cold fetch. A
  persisted-but-not-yet-refreshed snapshot counts as stale and is
  subject to `maxStaleness`.
- **Cold start, no persisted snapshot.** Block handshakes until the
  first `getProgramAccounts` completes (~hundreds of ms). The server
  never admits what it cannot authorize.

## Client flow

A terminal can't talk to a browser wallet extension directly, so the
wallet signs through a browser hand-off. The crucial design choice:
**the browser signs a [Layer-2 delegation](#three-layers), not the
live handshake nonce.** That keeps the wallet off the connection hot
path.

### The agent key

`mosey attach` mints an ephemeral **agent key** `K_c` (Ed25519, in
memory) — the same key that serves as the transport `peerPubKey`.
The wallet delegates *to* `K_c`; thereafter `K_c` does the live
signing. So:

- The wallet only ever runs `signMessage` (off-chain) — it never
  sees `K_c`'s private key, never signs a live nonce, never submits
  a transaction.
- The wallet step happens **once per grant-lifetime**, not once per
  connect: reconnects and [pty-resume](reattach.md) reuse the cached
  delegation with no human in the loop.
- Replay binding is intact: the delegation names `K_c.pub`, and the
  handshake binds `K_c` to the connection by signing
  `nonce_s ‖ K_c.pub ‖ sessionId`. A stolen delegation is useless
  without `K_c`'s private key.

### The browser hand-off (loopback)

The `gh auth login` / `solana` / `gcloud` pattern, with one
refinement: **the CLI serves the signing page itself from
`127.0.0.1`** — no third-party `wallet.mosey.dev` origin in the trust
path, and wallet extensions inject fine on `http://localhost`.

```
mosey attach <endpoint> --caps write
   │
   ├─ grant cache hit for (sessionId, wallet)? ── yes ─▶ handshake (no browser)
   no
   │
   ├─ mint ephemeral K_c
   ├─ start loopback server on 127.0.0.1:<rand>   (serves SPA + callback)
   ├─ open browser → http://127.0.0.1:<port>/authorize
   │       #session=<id>&delegate=<Kc.pub>&caps=write&state=<csrf>
   ▼
 [browser] wallet adapter connects → human-readable message:
   "Grant mosey session <id> WRITE to key <Kc> until <time>"
   user approves → wallet.signMessage(...)
   POST {delegation, walletPubkey, signature} → 127.0.0.1/cb
   │
   ▼
 CLI: verify state (CSRF) → cache grant (~/.mosey/grants/<sessionId>.json)
      → shut loopback server
   │
   ▼
 Handshake (Layer 3): K_c signs nonce_s; present [wallet→K_c] delegation
```

Pinned details:

- **Params travel in the URL fragment**, not the query string — the
  fragment never reaches a server (not even the loopback server's
  logs). A `state` nonce binds the callback to this exact invocation;
  the loopback listener is `127.0.0.1`-only, random single-use port,
  short timeout.
- **The signed message is human-readable** (Solana off-chain message
  format) so the wallet's approval dialog shows precisely what access
  is granted, to which key, until when.
- **Headless escape hatch:** `--keypair ~/.config/solana/id.json`
  (the Solana CLI standard) signs the delegation locally with no
  browser — for servers, CI, and the [devnet tier](#recommendation-solana).

### Forging a viewer grant

`mosey grant` produces access for someone else. There are two
**distribution channels** — the difference is where the grant lives
and what (if anything) has to travel from owner to viewer.

```
# Off-chain — free, emits a credential the owner must deliver
mosey grant --session <id> --caps view --expires 24h [--to <viewerWallet>]
   → a wallet-signed delegation blob / URL / QR

# On-chain — a transaction (free on devnet), nothing to deliver
mosey grant --session <id> --caps view --expires 24h --to <viewerWallet> --onchain
   → mints grant[sessionId][viewerWallet] on Solana
```

| Channel | How | Trade |
|---|---|---|
| **Off-chain bearer** (default) | Owner delegates to a fresh `K_c`, hands the viewer that key + delegation. Viewer runs `mosey attach --grant <blob>` — **no wallet, no browser, no Solana setup.** | Free + zero viewer setup, but you **must deliver a secret blob**; transferable to anyone who holds it. |
| **Off-chain wallet-bound** (`--to`) | Owner delegates to the viewer's *wallet*; viewer's wallet sub-delegates to its `K_c`. Chain `owner → viewerWallet → K_c`. | Free + can't be forwarded, but you **still must deliver the blob**; viewer needs a wallet. |
| **On-chain mint** (`--to … --onchain`) | Program writes `grant[sessionId][viewerWallet] = caps` (gated by the owner's on-chain `canForge`). | **Nothing to deliver** — owner needs only the viewer's address; auditable; clean revocation. Costs a tx (free on devnet) and the viewer needs a wallet. |

The on-chain mint is what your instinct was after: the chain *is* the
distribution channel. The owner needs only the viewer's public address
— shareable, reusable identity, not a one-time secret — and the viewer
**attaches exactly like the owner**: same loopback flow, self-issuing
its own local `wallet → K_c` delegation (which never leaves the
viewer's machine). The only difference is that the server discovers
the viewer's caps by reading `grant[sessionId][wallet]` from its
[snapshot](#chain-selection), rather than folding a client-presented
`owner → viewer` delegation. No blob ever changes hands.

In every channel the `canForge` cap is what authorizes the grant, and
its absence from what the viewer receives is what stops them
re-granting — enforced by the server's attenuation check off-chain,
and additionally by the program at mint time on-chain.

## Wire format

Three signed artifacts, all following `api/cert.proto`'s `content` +
`signature` split. Two are machine signatures (the handshake proofs);
one is human-signed (the delegation, approved in the wallet).

### Handshake (`/mosey/auth/1.0.0`)

A new `WalletHandshakeMessage` oneof, symmetric and **mutual** like the
cert handshake:

```protobuf
message WalletHandshakeMessage {
  oneof kind {
    WalletHello     hello     = 1;
    WalletChallenge challenge = 2;
    WalletProof     proof     = 3;
  }
}
message WalletHello {
  bytes client_pubkey = 1;             // K_c.pub == peerPubKey
  bytes nonce_c       = 2;             // 32 random bytes
  repeated Delegation delegation_chain = 3;
}
message WalletChallenge {
  bytes session_key = 1;               // the on-chain session identity
  bytes nonce_s     = 2;               // 32 random bytes
  bytes server_sig  = 3;
}
message WalletProof { bytes client_sig = 1; }
```

```
server_sig = Ed25519_session_key("mosey-wallet-v1:server" ‖ nonce_c ‖ nonce_s ‖ session_id)
client_sig = Ed25519_K_c        ("mosey-wallet-v1:client" ‖ nonce_s ‖ nonce_c ‖ session_id)
```

- Nonces are single-use per connection; the proof must arrive within
  the handshake timeout. Direction-specific labels (`:server` /
  `:client`) stop a signature being replayed the other way.
- The server proves control of `session_key` via `server_sig`; the
  client checks it equals the session it dialed — so a man-in-the-
  middle can't impersonate the session.
- `client_sig` proves live control of `K_c`. Both proofs are
  machine-signed raw bytes — no human sees them.

### Delegation

Every delegation is wallet-signed, so its signed bytes are a
**canonical, human-readable text** (Sign-In-With-Solana style): what
the wallet displays is exactly what it signs.

```protobuf
message Delegation {
  bytes content   = 1;  // the UTF-8 canonical text below
  bytes signature = 2;  // Ed25519 over content, by the delegator named in content
}
```

The `content` grammar is fixed — strict field order, LF separators, no
trailing newline:

```
mosey session authorization v1

session: <base58 session_id>
delegator: <base58 pubkey>
delegate: <base58 pubkey>
caps: <write, resize, forge | view-only>
not-before: <RFC3339 UTC, seconds, Z>
not-after: <RFC3339 UTC, seconds, Z>
nonce: <base58 16-byte>
```

- Line 1 is the domain tag + version: it separates these bytes from
  any other `signMessage` payload and pins the format version.
- `caps` lists present bits in the fixed order `write, resize, forge`,
  lowercase, `", "`-joined; the empty set renders literally as
  `view-only`.
- Pubkeys/nonce are base58 (Solana convention); timestamps are strict
  RFC3339, UTC, seconds precision, literal `Z`, no fractional seconds —
  so Go and TS render byte-identical strings.
- Verification **re-parses `content` strictly** (off-grammar input is
  rejected, never coerced) and checks `signature` against the
  `delegator` named inside. This is the same artifact the loopback
  browser page returns and the CLI caches.
- The wallet signs the **raw UTF-8 bytes** of `content` via
  `signMessage` — no `\xffsolana offchain` envelope — and
  `crypto/ed25519.Verify` accepts them directly (validated by
  `spike/wallet-sig/`).

### Chain & resolution

`delegation_chain` is ordered root → leaf, and the server folds it:

```
chain[n].delegate == K_c.pub                  // leaf binds to the live key
chain[i].delegate == chain[i+1].delegator     // links join
chain[i+1].caps   ⊆ chain[i].caps             // attenuation
every signature valid; every [not-before, not-after] covers now
chain[0].delegator resolved against the snapshot:
    owner   ⇒ {write, resize, forge}
    grantee ⇒ grant caps  (must include FORGE to be a non-leaf delegator)
effective caps = fold(chain) ∩ snapshot caps of the root
```

- **On-chain path:** a single self-delegation `[W → K_c]`; `W`'s caps
  come from the [snapshot](#snapshot-and-freshness), and the
  self-delegation can only narrow them (`∩`), never widen.
- **Depth is capped** (~8 hops) to bound verification cost; over-long
  or cyclic chains are rejected.

## Revocation

- **Ownership:** transfer or burn the on-chain token. The server's
  next snapshot refresh drops the old owner's caps. Subscribe to
  the registry's transfer/burn events to refresh promptly.
- **On-chain grants:** the owner closes the grant PDA (a transaction,
  refunds rent). The server's next snapshot refresh drops the caps —
  no expiry needed, though one is still cheap insurance. This is the
  cleanest revocation path and a reason to mint on-chain for
  collaborators you may need to cut off precisely.
- **Off-chain delegations:** prefer short `notAfter` windows (minutes
  to hours) so most revocation is automatic. For immediate kill,
  reuse the existing revocation-list machinery — the server already
  reloads a revocation file on SIGHUP — keyed on the delegation
  nonce instead of a cert serial.
- **Live connections:** like certs today, revocation gates *new*
  handshakes, not connections already up. Killing an active viewer
  is a separate concern — `mosey control kick`.

## Where it plugs into the code

Enforcement is already generic (it only reads `CanWrite() /
CanResize() / IsOwner()`), so the surface area is the credential, not
the policy:

- `auth/wallet.go` — a new `Authenticator` beside `psk.go` /
  `cert.go`, implementing `ServerHandshake` / `ClientHandshake`.
- `api/auth.proto` — the `WalletHandshakeMessage` oneof (`WalletHello`,
  `WalletChallenge`, `WalletProof`) and the `Delegation`
  (`content` + `signature`) message. See [Wire format](#wire-format).
- A delegation type + verifier: render/parse the canonical
  SIWS-style `content` text, fold the chain, enforce
  `child.caps ⊆ parent.caps`, check the root against the chain
  snapshot. The on-chain path is the degenerate one-hop case —
  the client presents only its self-issued `wallet → K_c`, and caps
  come from the snapshot's grant record.
- A chain-snapshot cache (see [Snapshot and freshness](#snapshot-and-freshness)):
  warm-start from the persisted snapshot, `getProgramAccounts` to load
  `Session` + `Grant` records, `accountSubscribe` for fast revocation
  plus a backstop poll, on-demand verify on miss, fail-open within
  `maxStaleness`; the hot path reads only the in-memory snapshot.
- A persisted session keypair: an Ed25519 key under
  `~/.mosey/sessions/`, loaded on `launch`, reused as the libp2p
  `Options.Identity`, and used to derive the on-chain PDA. See
  [Session identity and resurrection](#session-identity-and-resurrection).
- `cmd/mosey/launch.go` — `--wallet-*` flags in
  `buildAuthenticator()` (session key path, RPC endpoint — devnet or
  mainnet-beta, `--program` override defaulting to the canonical id,
  `--snapshot` path, `--max-staleness`, `--commitment`).
- `clients/typescript/src/` — `runWalletHandshake()` and a
  `WalletAuthConfig` discriminant in the `connect()` dispatch;
  rendering the canonical delegation text for `wallet.signMessage`,
  and signing the live `client_sig` with the cached agent key `K_c`
  (`tweetnacl` Ed25519). The Go and TS renderers must produce
  byte-identical `content`.
- A loopback authorizer: a `127.0.0.1` HTTP server that serves the
  signing SPA (the **Phantom** injected provider — see scope below;
  `@solana/web3.js`) and the callback, plus a grant cache at
  `~/.mosey/grants/`. See [Client flow](#client-flow).
- `mosey grant` — off-chain by default (emits a delegation blob:
  bearer, or `--to <wallet>` wallet-bound) and `--onchain` to mint a
  grant PDA via the program; plus `--keypair` / `--grant` flags on
  `mosey attach`.
- The [Anchor program](#on-chain-program-anchor): `register_session`,
  `transfer_ownership`, owner-only `grant` / `revoke`, and
  `bump_epoch`; `Session` + `Grant` PDAs; events the snapshot cache
  subscribes to.
- New cap bit: `Forge`, alongside `Owner | Write | Resize`.
- Extend `TestIdentityOf_AcrossBackends` (see [auth.md](auth.md)) to
  cover a wallet credential before shipping.

## Decisions made

- **Chain: Solana.** Chosen for Ed25519 reuse with mosey's crypto;
  devnet for the free/non-critical tier, mainnet-beta when ownership
  is worth anchoring. See [Recommendation: Solana](#recommendation-solana).
- **`sessionId`: a persisted Ed25519 session keypair**, transport-
  independent, doubling as the libp2p host key and seeding the
  on-chain PDA. See
  [Session identity and resurrection](#session-identity-and-resurrection).
- **Client wallet UX: a loopback browser hand-off** that signs a
  delegation to an ephemeral agent key (not the live nonce); CLI
  serves the signing page from `127.0.0.1`. See [Client flow](#client-flow).
- **Two grant channels, both supported:** off-chain delegation blob
  (free, default; bearer or `--to` wallet-bound) and `--onchain` mint
  (a tx, free on devnet; nothing to transmit, on-chain revocation).
  See [Forging a viewer grant](#forging-a-viewer-grant).
- **Program shape** (see [On-chain program](#on-chain-program-anchor)):
  owner-only on-chain minting (deep delegation stays off-chain), plain
  `owner` field with `transfer_ownership`, auth-only (no endpoint
  on-chain), and a `bump_epoch` mass-revoke kill switch. PDAs:
  `Session = [b"session", session_key]`,
  `Grant = [b"grant", session, grantee]`.
- **Snapshot/freshness** (see [Snapshot and freshness](#snapshot-and-freshness)):
  per-session in-memory snapshot, asymmetric refresh (push for
  revocation, poll for new grants), `confirmed` commitment, fail-open
  within `maxStaleness`, on-demand verify on miss, warm-start from a
  persisted snapshot.
- **Wire format** (see [Wire format](#wire-format)): a symmetric,
  mutually-authenticated `WalletHandshakeMessage`; delegations as
  canonical SIWS-style human-readable text in a `content` +
  `signature` envelope; chains folded leaf-bound to `K_c` with
  attenuation against the snapshot root.
- **Wire format validated by spike** (`spike/wallet-sig/`): the
  canonical text renders byte-identically in TS and Go, and **Phantom**'s
  `signMessage` signs the **raw UTF-8 bytes** (no `\xffsolana offchain`
  envelope), which `crypto/ed25519` verifies.
- **Scope: Phantom only for now.** The first e2e target is Phantom.
  Other wallets (Solflare, Backpack, …) are deferred — once the e2e
  flow works, sanity-check each with `spike/wallet-sig/sign.html`
  before claiming support, since `signMessage` framing can differ.
- **Deployment & governance** (see
  [Deployment & governance](#deployment--governance)): one canonical
  reference program at a constant id, with a `--program` override for
  self-deployers; upgrade authority phased single key → multisig →
  burned to immutable.

## Open questions

None outstanding — the design is fully specified. Remaining work is
implementation (see [Where it plugs into the code](#where-it-plugs-into-the-code))
and the deferred multi-wallet sanity check.
