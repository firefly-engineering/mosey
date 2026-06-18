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

This is verified working on `aarch64-darwin`. Two nixpkgs frictions are
handled by the recipe (see `justfile`):

- the SBF SDK ships in the **read-only Nix store**, so `cargo-build-sbf`
  can't install platform-tools next to it — the recipe copies the SDK to
  a writable cache and points `SBF_SDK_PATH` there;
- the **default platform-tools (v1.51 / Rust 1.84) are too old** for the
  program's `edition2024` deps — the recipe pins `--tools-version v1.54`
  (Rust 1.89). First run fetches platform-tools over the network (impure;
  the fully-hermetic version is the eventual toolbox/FOD goal).

Deploy + IDL + on-chain tests (need a funded keypair / validator):

```sh
anchor build                      # IDL + .so via the same toolchain
solana program deploy --url devnet target/deploy/mosey_session.so
```

After the first deploy, set the real program id in `declare_id!` (it is
the placeholder system-program id today) and as mosey's canonical
`--program` default.

`target/` is gitignored; `Cargo.lock` is committed for reproducible builds.
