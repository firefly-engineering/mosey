# Wallet authentication: implementation plan

> Companion to the [wallet authentication proposal](wallet-auth.md).
> That doc is the *what* and *why*; this is the *how* and *in what
> order*. It is grounded in the current code — the `Authenticator`
> interface, `auth.Wrap`, `CertAuth` as the template, the `justfile`
> task runner, and the hand-rolled TS proto.

## Shape of the work

Two tracks that converge on one seam:

```
Track A — auth protocol (touches mosey, no chain)         Track B — chain
  A1 canonical delegation primitive (Go+TS, golden vector)  B1 Anchor program (devnet)
  A2 wire messages (proto)                                  B2 Solana SnapshotSource
  A3 Go WalletAuth authenticator  ─┐                        B3 mosey grant + governance
  A4 launch/attach wiring + session key │                          │
  A5 TS client + loopback (Phantom)     │                          │
                                        └──── SnapshotSource ───────┘
                                              (the seam)
```

**The seam** is a `SnapshotSource` interface: "given the session and a
wallet, what live caps does it have?" Track A builds against an
**in-memory fake** and is fully e2e-testable with no chain. Track B
implements the real Solana-backed source behind the same interface and
swaps it in. The two tracks share only the account semantics already
fixed in [the program spec](wallet-auth.md#on-chain-program-anchor),
so they can proceed largely in parallel after Phase 0.

This ordering front-loads the integration risk that *can't* be
deferred (the cross-language handshake) and defers the toolchain risk
that *can* (Anchor/Solana), while keeping a working, demoable slice
available from Phase A4 onward.

## Cross-cutting decisions & reconciliations

- **`K_c` is the cert `peer_pubkey` analog**, not the transport host
  key. The client generates an ephemeral Ed25519 key, sends its public
  half in `WalletHello`, and proves control by signing the live nonce —
  exactly as `CertAuth` proves `peer_pubkey`. `auth.Wrap` already
  correlates the authed connection to its app streams via `RemoteID`;
  wallet auth changes none of it. (The proposal's "`K_c == peerPubKey`"
  should be read in this sense — update that phrasing when convenient.)
- **Crypto reuses what exists.** Go `crypto/ed25519`, TS WebCrypto
  Ed25519 (`crypto.ts`). No new crypto deps; the Solana choice is what
  buys this.
- **Delegations are canonical text** (spike-validated), carried in a
  `Delegation{content, signature}` proto envelope. The handshake
  *messages* are protobuf: generated in Go via `just proto`,
  hand-rolled in TS `proto.ts` (mirroring the cert messages).
- **New Go dependency: `github.com/gagliardetto/solana-go`** for RPC
  reads, `accountSubscribe`, and account decoding (Track B only).
  Fallback if its transitive weight is unacceptable: hand-roll the
  three JSON-RPC calls we need (`getProgramAccounts`,
  `getAccountInfo`, `accountSubscribe`). Decide at B2.
- **Toolchain: Anchor/Solana/Rust are absent from the Nix flake.**
  Adding them cleanly is finicky; do not let it block Track A. Track B
  may start with a documented *local* toolchain and fold into the flake
  once stable. Keep `anchor build`/`test` out of `just check` until it
  is reproducible.
- **No master key.** Unlike cert auth, the root of trust is on-chain
  ownership — so there is no `mint-master` analog. The CLI surface is
  `mosey session …` (register/transfer/bump-epoch) and `mosey grant`.

## Phase 0 — Foundations & the seam

Goal: the decoupling interface + scaffolding, so A and B can diverge.

- New package `auth/wallet/` with the `SnapshotSource` interface:
  ```go
  type Snapshot interface {
      // OwnerCaps reports the session owner and, for any wallet,
      // its on-chain caps (owner ⇒ all; grantee ⇒ grant caps),
      // liveness already applied (epoch + expiry).
      Owner() ed25519.PublicKey
      CapsOf(wallet ed25519.PublicKey) (Capabilities, bool)
      StaleFor() time.Duration // for the fail-open budget
  }
  type SnapshotSource interface { Current() Snapshot }
  ```
- An in-memory fake `SnapshotSource` for tests (configurable owner +
  grants).
- Create `programs/` and add Solana/Anchor/Rust to a dev shell
  (flake or documented local) — spike only; not wired into `just check`.

**Acceptance:** package compiles; fake snapshot has unit tests.

## Phase A1 — Canonical delegation primitive

Goal: promote the [spike](../../spike/wallet-sig/) into real modules
with a **committed cross-language golden vector** so byte-identity is
enforced forever, not just observed once.

- Go `auth/wallet/delegation.go`: `RenderContent(fields)`,
  `ParseContent` (strict, off-grammar rejected), `VerifyDelegation`
  (Ed25519 over `content` by the named `delegator`), and `Fold(chain,
  leafPub, snap)` implementing the [chain rules](wallet-auth.md#chain--resolution).
- TS `clients/typescript/src/wallet-delegation.ts`: render + parse.
- `testdata/delegation-vectors.json` exercised by **both** the Go test
  (`just test`) and the TS test (`just ts-test`) — the permanent
  successor to the spike.

**Acceptance:** Go and TS produce identical `content` for every vector;
round-trip parse; tampered signature/grammar rejected.

## Phase A2 — Wire messages

- `api/wallet.proto`: `WalletHandshakeMessage` (oneof
  `hello`/`challenge`/`proof`), `WalletHello`, `WalletChallenge`,
  `WalletProof`, `Delegation`. Add it to the `just proto` and
  `proto-check` recipes; regenerate `api/wallet.pb.go`.
- TS: hand-roll encode/decode in `proto.ts` mirroring the cert helpers.

**Acceptance:** `just proto-check` clean; TS proto round-trip tests pass.

## Phase A3 — Go `WalletAuth` authenticator

Goal: the authenticator, tested against the fake snapshot — no chain.

- `auth/wallet.go`: `WalletAuth` implementing `Authenticator`.
  - `ServerHandshake`: send `WalletChallenge{session_key, nonce_s,
    server_sig}`, read `WalletHello`, fold the chain against
    `SnapshotSource`, verify `client_sig` over `nonce_s`, return
    `Identity`.
  - `ClientHandshake`: send `WalletHello{K_c.pub, nonce_c, chain}`,
    verify `server_sig` (session matches what we dialed), sign
    `nonce_s` with `K_c`.
  - Domain labels `mosey-wallet-v1:{server,client}`; mutual but
    *asymmetric* (server proves session identity, client proves K_c +
    presents chain).
- Tests: owner attaches; grantee via 1-hop on-chain self-delegation;
  multi-hop off-chain chain; rejects over-attenuation, expired window,
  wrong leaf, wrong session_key.

**Acceptance:** unit tests green with the fake snapshot.

## Phase A4 — launch/attach wiring + session identity — *first slice*

- `cmd/internal/walletflags/` mirroring `certflags` (`Register` /
  `Configured` / `Build`). Server flags: `--wallet-session-key`,
  `--program`, `--rpc`, `--snapshot`, `--max-staleness`,
  `--commitment`. Client flags: `--wallet-keypair`, `--wallet-grant`.
- Persisted **session keypair**: load/generate Ed25519 under
  `~/.mosey/sessions/`, feed to libp2p `Options.Identity`, derive
  `session_id`. (See [session identity](wallet-auth.md#session-identity-and-resurrection).)
- Wallet branch in `buildAuthenticator` (launch.go) and
  `buildAttachAuthenticator` (attach.go).
- A dev stub: `--wallet-dev-owner <pubkey>` selects the in-memory
  `SnapshotSource`, so the whole path is exercisable with no chain.
- Go e2e mirroring `TestIdentityOf_AcrossBackends`: launch with wallet
  auth + dev snapshot; attach with a locally-signed delegation.

**Acceptance:** `mosey launch`/`attach` authenticate end-to-end over
the wallet path with no chain — the demoable vertical slice.

## Phase A5 — TS client + loopback signing (Phantom)

- `clients/typescript/src/wallet-auth.ts`: `runWalletHandshake`
  mirroring `runCertHandshake`; `WalletAuthConfig` in `client.ts`;
  `runAuth` dispatch.
- **Loopback authorizer** in the CLI (Go `127.0.0.1` HTTP server)
  serving the signing SPA (promote `spike/wallet-sig/sign.html`,
  Phantom only) + the callback, with the grant cache at
  `~/.mosey/grants/`. See [client flow](wallet-auth.md#client-flow).
- TS e2e: sign a delegation with a local Ed25519 key (stand-in for the
  wallet) and attach. Manual check: the Phantom loopback flow against a
  live `mosey launch`.

**Acceptance:** TS client attaches via the wallet path; the manual
Phantom loopback flow works.

## Phase B1 — Anchor program (devnet)

- `programs/mosey-session/`: `Session` + `Grant` accounts;
  `register_session` (co-signed by the session key),
  `transfer_ownership`, owner-only `grant` / `revoke`, `bump_epoch`;
  events. PDAs per [the spec](wallet-auth.md#on-chain-program-anchor).
- `anchor test` on localnet; deploy to devnet; record the program id
  as the canonical default (with `--program` override).

**Acceptance:** anchor tests green; deployed to devnet.

## Phase B2 — Solana-backed `SnapshotSource`

- `auth/wallet/snapshot_solana.go` over `solana-go`:
  `getProgramAccounts(memcmp session)` seed; `accountSubscribe` on the
  Session PDA + known Grant PDAs (fast revocation) + backstop poll (new
  grants, heal); `confirmed` commitment; **fail-open within
  `maxStaleness`**; **on-demand `getAccountInfo` on miss** (short
  timeout, rate-limited); **warm-start** from the `--snapshot` file.
  All per [snapshot & freshness](wallet-auth.md#snapshot-and-freshness).
- Swap the fake for the real source in the launch wiring; decide
  `solana-go` vs hand-rolled RPC here.

**Acceptance:** against the B1 program, the server resolves owner +
grant caps; `revoke` / `bump_epoch` reflected within the budget;
RPC-outage falls open then closed at `maxStaleness`.

## Phase B3 — `mosey grant` + `mosey session` + governance

- `mosey grant`: off-chain (sign the canonical delegation via loopback
  or `--wallet-keypair`, emit a blob — **bearer default**, `--to` for
  wallet-bound) and `--onchain` (submit the `grant` ix via `solana-go`).
- `mosey session register|transfer|bump-epoch`: thin wrappers over the
  program instructions.
- Governance (ops, not code): single key on devnet → Squads multisig
  on mainnet bring-up → burn to immutable. See
  [deployment & governance](wallet-auth.md#deployment--governance).

**Acceptance:** both grant channels yield working access; an on-chain
grant attaches with nothing transmitted but the viewer's address.

## Phase C — Hardening & deferred checks

- Multi-wallet sanity (Solflare, Backpack) via `sign.html` — the
  deferred check, now that e2e exists.
- Extend `TestIdentityOf_AcrossBackends` with a wallet credential
  (the proposal pins this as a ship gate).
- Fuzz the strict `content` parser; enforce the ~8-hop depth cap;
  rate-limit on-demand verify.
- Fold the validated bits back into the proposal; write an ops runbook
  (deploy, multisig, burn, key handling).

## Dependencies & parallelism

```
0 ─┬─ A1 ─ A2 ─ A3 ─ A4 ─ A5 ─┐
   │                          ├─ C
   └─ B1 ─ B2 ─ B3 ───────────┘
            ▲
            └ needs A3's SnapshotSource seam + B1's program
```

- **Critical path** to a demoable slice: 0 → A1 → A2 → A3 → A4.
- A5 and the whole B-track can run alongside once A3 fixes the seam.
- B2 is the only place the tracks truly meet (real source behind the
  interface A3 consumed as a fake).

## Risks

| Risk | Mitigation |
|---|---|
| Anchor/Solana toolchain in Nix is finicky | Track B starts on a documented local toolchain; keep `anchor` out of `just check` until reproducible; never block Track A. |
| `solana-go` transitive weight | Spike it at B2; fall back to hand-rolled JSON-RPC for the three calls we use. |
| Go/TS canonical-text drift | The A1 golden vector is a permanent CI gate (`just check` + `just ts-check`). |
| `accountSubscribe` WS drops silently | Backstop poll is mandatory, not optional (already in the design). |
| Devnet program id churn during dev | `--program` override; bake the canonical id only after a stable deploy. |
| Phantom-only assumption | Scoped deliberately; Phase C sanity-checks others before widening. |

## Implementation status

Built and tested in this repo (Go `go test ./...`, TS `vitest`, Rust
`cargo check`):

| Phase | What landed | Verification |
|---|---|---|
| 0 | `wallet` pkg: `Caps`, `Snapshot`/`SnapshotSource`, in-memory source | unit |
| A1 | canonical delegation render/parse/`Sign`/`Verify`/`Fold` (Go + TS) | unit + **cross-language golden vector** |
| A2 | `api/wallet.proto` + generated Go + hand-rolled TS codecs | `proto-check` + round-trip |
| A3 | `auth.WalletAuth` (mutual handshake, chain fold, fail-closed/on-demand) | unit over `net.Pipe` |
| A4 | `walletflags`, launch/attach wiring, session keypair | unit + **e2e through `auth.Wrap` over unix + websocket** |
| A5 (client) | `runWalletHandshake`, `WalletAuthConfig`, `Stream.whenClosed` | **TS e2e against a live `mosey launch`** (happy + reject) |
| A5 (loopback) | `mosey wallet sign` 127.0.0.1 authorizer + Phantom SPA | handler tests w/ in-process signer; **live Phantom is manual** |
| B1 | `programs/mosey-session` Anchor program | `cargo check` (host) + **`just anchor-build` produces the `.so`** under nixpkgs solana-cli/anchor |
| B2 | `walletsolana` Solana `SnapshotSource` | unit w/ fake RPC caller |
| B3 (off-chain) | `mosey grant` (bearer + `--to`) | **e2e: grant → attach** |
| C | strict-parser fuzz; 8-hop depth cap; owner/admin scoping fix | fuzz (8.5M execs) + unit |

Deferred — each blocked only by infrastructure absent from this
workspace, not by design:

- **B1 deploy + `anchor test`** — the program now **builds** under the
  Nix dev shell (`just anchor-build` → `.so`, verified). Deploying
  (`solana program deploy`) needs a funded keypair; `anchor test` needs
  a running validator. Deploy then sets the real `declare_id!` /
  canonical `--program`.
- **B2 live verification** — needs the program deployed to devnet; the
  decode/liveness/budget logic is already unit-tested.
- **B3 on-chain writes** (`mosey session register/transfer/bump-epoch`,
  `grant --onchain`) — transaction construction + submission needs a
  Solana SDK and a deployed program to build against. The off-chain
  grant channel is complete; the on-chain channel is the chain-write
  client, to be added with the toolchain.
- **A5 multi-wallet** (Solflare, Backpack) and the live Phantom flow —
  need real browsers/extensions; `spike/wallet-sig/sign.html` and
  `mosey wallet sign` are ready for the manual pass.
- **`accountSubscribe` push refresh** — the poll backstop (the
  correctness floor) is implemented; WS push is a latency optimization.
- **Nix flake** — `solana-cli` + `anchor` are in the dev shell and
  `just anchor-build` builds the program **offline**: platform-tools
  v1.54 is pinned as a fixed-output derivation, mounted into a complete
  SBF SDK, and used via `--skip-tools-install` (no build-time download,
  verified on `aarch64-darwin`). Remaining: fill the platform-tools
  hashes for the other three systems and move the whole thing into the
  toolbox; consider a `.#onchain` shell to keep the ~300 MiB off the
  default shell. Kept out of `just check`.
