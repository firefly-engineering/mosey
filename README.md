# mosey

> _"I think we should mosey." — Malcolm Reynolds_

`mosey` is a peer-to-peer terminal-sharing primitive. Run a process
under a virtual terminal that's reachable over libp2p (or HTTP/2),
then attach to it from another machine — the way you'd `tmux`
attach, but across hosts, without a central rendezvous server.

Extracted from [shepherd](https://github.com/firefly-engineering/shepherd)
so its process-attach primitives can stand alone.

## Status

Pre-v0.1. The wire model, multi-client modes, control protocol,
cert auth, and reattach-with-replay are implemented and tested. The
binary surface and protocol IDs are not yet frozen.

## Install

```sh
go install github.com/firefly-engineering/mosey/cmd/mosey@latest
```

Or, with Nix:

```sh
nix build github:firefly-engineering/mosey
./result/bin/mosey help
```

## Quick demo (PSK)

```sh
# Host A — launch a shell behind a shareable PTY.
$ mosey launch --secret=hunter2 -- bash
mosey launch: listening: /ip4/192.168.1.10/tcp/4001/p2p/12D3KooW...

# Host B — attach. You're now sharing the host-A shell.
$ mosey attach --secret=hunter2 /ip4/192.168.1.10/tcp/4001/p2p/12D3KooW...
hostA $
```

The shared secret is required on both sides. For multi-tenant
workspaces with revocation, mint per-agent certs from a master
keypair — see [docs/src/auth.md](docs/src/auth.md).

## Subcommands

```text
mosey launch  [flags] -- PROGRAM [ARGS...]   run PROGRAM under a shareable PTY
mosey attach  [flags] ENDPOINT                connect to a running launch
mosey control SUBCMD [flags] ENDPOINT ...     admin ops (list-clients, promote, kick, demote, set-mode)
mosey cert    SUBCMD [flags] ...              workspace master + cert minting
```

Run `mosey SUBCMD -h` for per-subcommand flags.

## Design

See [docs/src/design.md](docs/src/design.md) for the wire model,
protocol IDs, transport backends, multi-client modes, and the
reattach / replay protocol. The full book lives under `docs/src/`.

## Clients

- **Go**: the `mosey` binary itself is the reference Go client
  (see `attach/` for the dialer + `cmd/mosey/attach.go`
  for the CLI wrapper).
- **TypeScript / browser**:
  [`clients/typescript/`](clients/typescript/) is the reference
  WebSocket client — PSK auth, PTY stream, control resize. Works
  in any modern browser or Node 22+; pairs naturally with
  `xterm.js` (see `clients/typescript/examples/xterm-demo.html`).

## Repo

Working in the repo? Start with [AGENTS.md](AGENTS.md) — it covers
the jj workflow, layout, and the build / test cadence.
