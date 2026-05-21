# Introduction

`mosey` is a small Go tool that runs a process under a virtual
terminal and lets other machines attach to it. Think `tmux`, except
the attaching peer doesn't need to share a filesystem or a kernel
with the host — they only need network reachability.

## What problem does it solve?

Coordinating with a long-running interactive process on a remote
host is awkward. You can SSH in and run it under `tmux` or
`screen`, but then everyone shares one POSIX session and every
attaching peer needs SSH credentials. You can wrap it in a web UI,
but now you're maintaining a web UI.

mosey instead exposes the process's PTY directly over an
authenticated peer-to-peer connection. Attaching is as cheap as
opening a libp2p stream; the host program never knows that more
than one observer is watching.

The transport plumbing — NAT traversal via libp2p's DCUtR, HTTPS
fallback for proxy-only environments, a typed control channel for
resize / signals / state events — handles the unfun parts so the
calling project can focus on the agent / session abstractions
layered on top.

## Where it came from

mosey is the cross-host attach layer extracted from
[shepherd](https://github.com/firefly-engineering/shepherd), where
it carries the daemon-to-agent PTY streams. Splitting it out makes
the abstraction independently testable and reusable; shepherd
depends on the same protocol IDs documented here.

## What it isn't

- **Not a tmux replacement.** No window management, no scrollback
  search, no key bindings. mosey gives you exactly one PTY per
  launch.
- **Not a multiplayer text editor.** Multi-writer mode exists but
  it's a deliberate-co-pilot tool, not a CRDT — bytes arrive in the
  order the kernel scheduled the writes.
- **Not a rendezvous-free protocol.** Two peers need to learn each
  other's libp2p multiaddr somehow. mosey doesn't include a
  discovery layer; the calling project supplies the endpoint
  string.

## Where to go next

- [Quickstart](quickstart.md) — the smallest demo that works.
- [CLI](cli.md) — every subcommand and flag.
- [Wire model](design.md) — what's actually on the network.
