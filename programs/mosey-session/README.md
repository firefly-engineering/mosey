# mosey-session (Anchor program)

The on-chain root of trust for [wallet auth](../../docs/src/wallet-auth.md#on-chain-program-anchor):
session ownership + owner-issued grants, with events the mosey server's
snapshot cache follows.

- `Session` PDA `[b"session", session_key]` — `session_key`, `owner`, `epoch`.
- `Grant` PDA `[b"grant", session, grantee]` — `caps` (WRITE|RESIZE|FORGE), `expiry`, `epoch`.
- Instructions: `register_session` (co-signed by the session key),
  `transfer_ownership`, owner-only `grant` / `revoke`, `bump_epoch`.

## Status & toolchain

The dev shell provides `solana-cli` + `anchor` (from nixpkgs). Build the
deployable `.so` with:

```sh
just anchor-build                 # → target/deploy/mosey_session.so
```

The build is **offline / pinned** (verified on `aarch64-darwin`): the
flake fetches platform-tools v1.54 as a fixed-output derivation, mounts
it into a complete SBF SDK, and exports `MOSEY_SBF_SDK`. `just
anchor-build` uses it with `--skip-tools-install`, so nothing is
downloaded at build time. This sidesteps two nixpkgs frictions: the
SBF SDK ships read-only in the store (so `cargo-build-sbf` can't install
platform-tools next to it), and the default platform-tools (v1.51 /
Rust 1.84) predate the program's `edition2024` deps (v1.54 ships Rust
1.89).

The platform-tools hash is pinned per system in `flake.nix`; only
`aarch64-darwin` is filled today (others are a TODO for the toolbox
move). On a system without a pinned hash, the recipe falls back to a
writable copy + a one-time platform-tools fetch.

(`cargo-build-sbf` logs a benign `ln: ... 'criterion': Permission
denied` — it tries to drop a bench symlink into the read-only SDK; the
`.so` is still produced.)

Deploy + IDL + on-chain tests (need a funded keypair / validator):

```sh
anchor build                      # IDL + .so via the same toolchain
solana program deploy --url devnet target/deploy/mosey_session.so
```

After the first deploy, set the real program id in `declare_id!` (it is
the placeholder system-program id today) and as mosey's canonical
`--program` default.

`target/` is gitignored; `Cargo.lock` is committed for reproducible builds.
