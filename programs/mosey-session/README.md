# mosey-session (Anchor program)

The on-chain root of trust for [wallet auth](../../docs/src/wallet-auth.md#on-chain-program-anchor):
session ownership + owner-issued grants, with events the mosey server's
snapshot cache follows.

- `Session` PDA `[b"session", session_key]` — `session_key`, `owner`, `epoch`.
- `Grant` PDA `[b"grant", session, grantee]` — `caps` (WRITE|RESIZE|FORGE), `expiry`, `epoch`.
- Instructions: `register_session` (co-signed by the session key),
  `transfer_ownership`, owner-only `grant` / `revoke`, `bump_epoch`.

## Status & toolchain

`cargo check` passes on the host (type-checks the program, account
constraints, and Anchor macros). A **deployable** build and on-chain
tests need toolchain not present in this workspace:

- `solana` CLI (provides `cargo-build-sbf` / the SBF platform tools)
- `anchor` CLI (`anchor build`, `anchor test`, IDL generation)

With those installed:

```sh
anchor build                      # produces target/deploy/mosey_session.so + IDL
anchor test                       # localnet integration tests
solana program deploy \           # deploy (devnet shown)
  --url devnet target/deploy/mosey_session.so
```

After the first deploy, set the real program id in `declare_id!` (it is
the placeholder system-program id today) and as mosey's canonical
`--program` default.

`target/` is gitignored; `Cargo.lock` is committed for reproducible builds.
