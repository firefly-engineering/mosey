# Agent Instructions

This file is the single source of truth for how to work in this
repository, whether you're a human contributor or an AI agent. Keep
it current: when workflow or repo conventions change, the change
lands here in the same PR.

The user-facing description and quick demo live in
[`README.md`](README.md). The design contract lives in
[`docs/src/design.md`](docs/src/design.md). Read both before
touching code.

---

## Layout

```
cmd/
  mosey/                 the only released binary (launch | attach | control | cert)
  internal/certflags/    shared --cert/--key/--master-pub flag bundle
internal/
  api/                   wire protos (auth, control, cert) + protocol IDs
  attach/                client side: dial /ship/pty/, reconnect-with-replay
  auth/                  Authenticator interface, PSK + cert impls, Wrap()
  cert/                  Sign/Verify, revocation file, BIP-39 master
  streambuf/             OutputRing — sequence-tagged ring buffer for replay
  transport/             Transport / Stream interfaces, Multi aggregator
    libp2p/              production cross-host backend (TCP + QUIC + Noise + DCUtR)
    http2/               h2c + HTTPS backend, useful for browser / proxy environments
  vterm/                 session: PTY fan-out, per-client geometry, mode policy
docs/
  src/                   mdbook source (SUMMARY.md is the index)
```

## Build, test, run

```sh
go build ./...                       # everything builds
go test -timeout 90s ./...           # full suite (no -count needed for CI; use -count=3 to stress)
go run ./cmd/mosey help              # smoke-test the dispatcher
```

The Nix shell (`nix develop`, or `direnv allow` then auto-load via
`.envrc`) pins the Go toolchain and adds protoc + nixfmt-tree.
Without Nix, install Go 1.26.2 yourself and `protoc` + the Go
plugin if you need to regenerate `internal/api/*.pb.go`.

## Conventions

- **No comments that describe _what_ the code does.** Only the
  _why_ — hidden constraints, subtle invariants, workarounds. If
  removing the comment wouldn't confuse a reader, don't write it.
- **No backwards-compat shims** until something's tagged. Pre-v0.1
  we change wire IDs / flag shapes when the design wants it.
- **Tests touch real backends.** Never mock the libp2p / http2
  layer — the integration tests in `internal/transport/http2/` and
  `internal/vterm/` use ephemeral local listeners. If a flake
  appears, root-cause it (the auth handshake had to grow a sync
  byte for exactly this reason — see `internal/auth/wrap.go`).
- **Wire IDs are stable identifiers.** `/ship/auth/1.0.0`,
  `/ship/pty/1.0.0`, the HKDF labels (`ship-cert-v1`,
  `ship-cert-master`) — keep these spelled `ship`, even though the
  binary is `mosey`. They're protocol identifiers, not branding;
  rotating them silently breaks every workspace master ever minted.

## Version Control — Jujutsu (jj)

This repo uses `jj`. **Do not run git commands directly** — the
colocated `.git/` is for nix / GitHub interop; mutating it bypasses
jj's invariants.

### Critical rules

- **No editor-opening commands.** Always pass `-m` for messages.
  Never use `jj describe` without `-m`, `jj split` without `-m`,
  `jj squash` without `-m`, or `jj resolve`. They hang in
  non-interactive sessions.
- **There is no staging area.** Working-copy changes are
  automatically in commit `@`. No `add` step.
- **Snapshot before nix / go-tooling.** Both read via the
  underlying git repo. New / renamed files only become visible
  after a `jj status` (which implicitly snapshots).

### Commits

Use [Conventional Commits](https://www.conventionalcommits.org/),
lowercase, no emojis:

```
<type>(<scope>): <description>

[optional body]
```

| Type | Use |
|---|---|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `refactor` | No behavior change |
| `docs` | Documentation only |
| `test` | Test additions / improvements |
| `chore` | Build, deps, infra |

One jj change per PR. Always `jj new @ -m '...'` between stack
members before editing files; post-hoc splitting via `jj split` is
fragile.

## Releasing

Pre-v0.1: there are no releases. When v0.1 lands, the release
process will mirror shepherd's (a tag, a changelog entry, a Nix
build). The single `mosey` binary keeps the release surface tiny.
