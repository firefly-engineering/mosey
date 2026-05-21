# Quickstart

Two hosts on the same LAN. Replace the multiaddr in the second
step with whatever the first step prints.

## 1. Launch on host A

```sh
$ mosey launch --secret=hunter2 -- bash
mosey launch: listening: /ip4/192.168.1.10/tcp/4001/p2p/12D3KooWAbCdEf...
mosey launch: listening: /ip4/192.168.1.10/udp/4001/quic-v1/p2p/12D3KooWAbCdEf...
hostA $
```

`mosey launch` runs `bash` under a PTY and announces listeners on
TCP and QUIC. Stop with Ctrl-D inside `bash` or SIGTERM from
outside.

## 2. Attach from host B

```sh
$ mosey attach --secret=hunter2 /ip4/192.168.1.10/tcp/4001/p2p/12D3KooWAbCdEf...
hostA $
```

You're now sharing the same shell as host A. Type, resize, exit —
both sides see it. By default host A's most recent attacher wins
write permission (`--mode=supersede`); see
[multi-client modes](multi-client.md) for the alternatives.

## 3. Add a second attacher (optional)

```sh
$ mosey attach --secret=hunter2 /ip4/192.168.1.10/tcp/4001/p2p/12D3KooWAbCdEf...
```

In supersede mode this kicks B and seats C as the new writer. In
`--mode=primary-observer` C arrives as a read-only observer. In
`--mode=multi-write` all three (A's owner, B, C) type into the same
terminal.

## HTTPS instead of libp2p

For proxy-restricted environments, swap the listener URI:

```sh
# host A
$ mosey launch \
    --secret=hunter2 \
    --listen=https://0.0.0.0:8443 \
    --http-cert=./cert.pem --http-key=./key.pem \
    -- bash

# host B
$ mosey attach \
    --secret=hunter2 \
    --insecure-tls \                # only for self-signed dev certs
    https://hostA.example:8443
```

The two backends coexist — pass `--listen` multiple times to expose
the same vterm over libp2p AND HTTPS.

## Workspace certs instead of a PSK

For environments with rotating membership, replace `--secret` with
a workspace master + per-agent certs. See [auth](auth.md) for the
full minting flow. The TL;DR:

```sh
$ mosey cert mint-master --out=./ws
$ mosey cert mint-agent --master-key=./ws/master.key \
                         --workspace=demo --label=alice --out=./ws
$ mosey launch \
    --cert=./ws/alice.cert --key=./ws/alice.key \
    --master-pub=./ws/master.pub --workspace=demo \
    -- bash
```

The attacher dials with its own cert; the launcher trusts any cert
signed by the master public key it carries.
