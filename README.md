# ship

Run a process under a virtual terminal that's reachable over libp2p,
then attach to it from another machine.

## Status

Pre-alpha. End-to-end PTY bytes work; control protocol (resize,
signals, state) is the next milestone. Extracted from
[shepherd](https://github.com/firefly-engineering/shepherd) so its
process-attach primitives can stand alone.

## CLI

```sh
# host A: run a program inside a vterm reachable over libp2p
$ vterm --secret=hunter2 -- bash
listening at /ip4/192.168.1.10/tcp/4001/p2p/12D3KooW...

# host B: attach to it
$ attach --secret=hunter2 /ip4/192.168.1.10/tcp/4001/p2p/12D3KooW...
$ # bash prompt from host A — type, exit, etc.
```

The shared secret is required on both sides — without it, the libp2p
private-network protector rejects the handshake before any
application protocol surfaces. Future versions add a cert-based
authenticator alongside the PSK one (the interface is already
abstracted).

## Design

See `docs/design.md` for the wire model, protocol IDs, and the
roadmap toward a control protocol + workspace federation.
