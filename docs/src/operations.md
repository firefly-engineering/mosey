# Operations playbook

Day-two tasks against a running `mosey launch`. All admin commands
dial the same control stream `mosey attach` uses, so they take the
same auth flags.

## Find out who's attached

```sh
$ mosey control list-clients --secret=hunter2 ENDPOINT
ID  LABEL   WRITE  COLSxROWS
1   owner   yes    160x52
2   reader  no     120x36
```

The `ID` column is the stable handle for the other control verbs.

## Hand the keyboard to someone else

```sh
$ mosey control promote --secret=hunter2 ENDPOINT 2
```

In `primary-observer` mode this moves the writer seat to client 2
and demotes the prior primary to observer. In `multi-write` /
`supersede` / `exclusive` it's mostly a no-op since the cap layer
already determines who can write — useful for symmetry with
`demote` only.

## Step down voluntarily

```sh
$ mosey control demote --secret=hunter2 ENDPOINT
```

Drops your own `Write` + `Resize`. No cap required — anyone can
demote themselves. The "going AFK and don't trust myself not to
typo" pattern.

## Kick a client

```sh
$ mosey control kick --secret=hunter2 ENDPOINT 2
```

Closes client 2's PTY stream. The target's `mosey attach` exits
with `stream closed` and does **not** auto-reconnect (the control
stream sends an explicit kick reason; the reconnect loop respects
it).

## Change multi-client policy at runtime

```sh
$ mosey control set-mode --secret=hunter2 ENDPOINT exclusive
```

Modes: `supersede` (default), `exclusive`, `primary-observer`,
`multi-write`. The new mode applies to **future** attaches —
existing clients keep their permissions. Combine with `demote` /
`kick` to migrate the active set.

## Revoke a compromised cert

1. Append the serial to the revocation file:

   ```sh
   $ mosey cert revoke --revocation-file=/etc/mosey/revoked.txt \
                       --serial=01HZAB...XYZ
   ```

2. Send SIGHUP to the running `launch`:

   ```sh
   $ pkill -HUP -f 'mosey launch'
   ```

   The vterm logs `revocation list reloaded entries=N` at info
   level and immediately starts refusing the revoked serial.

The revocation file is plain-text, one serial per line, comments
beginning with `#`. Parsing is liberal — a malformed file logs a
warning and keeps the previous list rather than failing closed.

## Rotate a workspace master

The master keypair itself can't rotate without re-minting every
cert (the master public key is baked into every peer via
`--master-pub`). Rotation procedure:

1. Mint a new master: `mosey cert mint-master --out=./ws-new`.
2. Re-mint every active agent cert against the new master.
3. Distribute the new `master.pub` to every peer.
4. Restart all `mosey launch` and `mosey attach` processes against
   the new master.
5. Once you've confirmed everyone's on the new master, shred the
   old master key + mnemonic.

Plan to do this approximately never, unless the master leaks.

## Run multiple listeners at once

```sh
$ mosey launch \
    --secret=hunter2 \
    --listen=libp2p:// \
    --listen=https://0.0.0.0:8443 \
    --http-cert=./cert.pem --http-key=./key.pem \
    -- bash
```

Both backends accept the same auth flow and dispatch to the same
vterm session. Useful when some attachers are local (libp2p reaches
them) and others come through a TLS-terminating ingress.

## Read-only audit mode

Use the optional reader PSK:

```sh
$ mosey launch \
    --secret=hunter2 --reader-secret=peeker \
    -- bash
```

Hand `peeker` to the auditor; they dial with `--secret=peeker` and
get attached with empty caps (no write, no resize). Use
`mosey control list-clients` to confirm they show up as
`WRITE=no`.
