# mosey-session (Anchor program)

The on-chain root of trust for [wallet auth](../../docs/src/wallet-auth.md#on-chain-program-anchor):
session ownership + owner-issued grants, with events the mosey server's
snapshot cache follows.

- `Session` PDA `[b"session", session_key]` — `session_key`, `owner`, `epoch`.
- `Grant` PDA `[b"grant", session, grantee]` — `caps` (WRITE|RESIZE|FORGE), `expiry`, `epoch`.
- Instructions: `register_session` (co-signed by the session key),
  `transfer_ownership`, owner-only `grant` / `revoke`, `bump_epoch`.

## Status & toolchain

The dev shell provides the toolbox `solana-toolchain` (solana-cli +
anchor + a host-independent `cargo-build-sbf`). Build the deployable
`.so` with:

```sh
just anchor-build                 # → target/deploy/mosey_session.so
```

The build is **offline and host-independent** (verified on
`aarch64-darwin`): the toolchain pins platform-tools v1.54 as a
fixed-output derivation, mounts it into a complete SBF SDK, runs against
an isolated `RUSTUP_HOME` with the platform-tools rust as the rustup
default, and passes `--skip-tools-install`. So nothing is downloaded at
build time and the host's `rustup` is never touched. (This sidesteps
nixpkgs shipping the SBF SDK read-only and its default platform-tools
predating the program's `edition2024` deps.) See
`toolbox//packages/solana-toolchain`.

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
