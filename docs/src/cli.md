# Command surface

All functionality lives behind one binary, `mosey`.

```
mosey launch  [flags] -- PROGRAM [ARGS...]
mosey attach  [flags] ENDPOINT
mosey web     [flags] --target ENDPOINT
mosey control SUBCMD [flags] ENDPOINT [...]
mosey cert    SUBCMD [flags] ...
```

Run `mosey SUBCMD -h` for the authoritative flag list. The sections
below cover intent and the non-obvious flags only.

## `mosey launch`

Runs `PROGRAM` under a PTY and announces listeners.

| Flag | Purpose |
|---|---|
| `--secret=PSK` | Pre-shared key for both ends. Mutually exclusive with `--cert`. |
| `--reader-secret=PSK` | Optional read-only PSK. Attachers presenting it can observe but not write/resize. |
| `--cert=...` / `--key=...` / `--master-pub=...` / `--workspace=ID` | Cert auth. See [auth](auth.md). |
| `--revocation-file=PATH` | File of cert serials to reject. SIGHUP reloads. |
| `--mode=MODE` | Multi-client policy: `supersede` (default), `exclusive`, `primary-observer`, `multi-write`. See [modes](multi-client.md). |
| `--listen=URI` | Repeatable. `libp2p://` (default — random TCP + QUIC ports), `http://host:port` (h2c), `https://host:port` (TLS), `unix:///path/to/sock` (same-host), `ws://host:port` (browser cleartext), or `wss://host:port` (browser TLS). |
| `--http-cert` / `--http-key` | Required when any `--listen` is `https://` or `wss://`. |
| `--no-p2p-bootstrap` | Skip the IPFS public bootstrap set. LAN-only / offline use. |
| `--log-level` | `debug` \| `info` \| `warn` (default) \| `error`. |

Exit code mirrors the child process when it exits cleanly, `1` on
operational errors, `2` on bad flags.

## `mosey attach`

Connects to a running `launch` and bridges the PTY to the local
terminal.

| Flag | Purpose |
|---|---|
| `--secret` / `--cert` / `--key` / `--master-pub` / `--workspace` | Same shape as `launch`'s auth side. Pick PSK or cert. |
| `--insecure-tls` | For `https://` endpoints with self-signed certs. Dev-only. |
| `--no-p2p-bootstrap` | LAN-only / offline. |

The single positional argument is the endpoint string the launcher
printed (a multiaddr or `https://host:port`).

Reconnect-with-replay is automatic: a transient network blip pauses
the local terminal for a few seconds, then resumes from the last
byte rendered. See [reattach](reattach.md).

## `mosey web`

Serves a browser terminal that bridges to a mosey host over libp2p — a
self-hosted gateway. Front it with an HTTPS proxy (e.g. `tailscale
serve`); browser wallets require a secure context. See
[web-attach](web-attach.md).

| Flag | Purpose |
|---|---|
| `--listen=ADDR` | HTTP listen address (default `127.0.0.1:8080`). The HTTPS front owns TLS. |
| `--target=ENDPOINT` | Host to bridge to (a multiaddr, `/p2p/<session-key>`, or `https://…`). Required except in multi-session mode. |
| `--secret` / `--cert=…` / `--wallet-grant=…` | Static auth: one host credential for every browser (gated by the network perimeter). |
| `--wallet-login` | Per-browser wallet login: each user signs a `W→K` delegation in the page and attaches with their own on-chain access. |
| `--session=BASE58` | Fixed-session `--wallet-login`: the session key the target host runs. |
| `--wallet-rpc=URL` / `--wallet-program=ID` | Enable the dashboard + multi-session attach (the browser lists and picks a session); supersedes `--session`/`--target`. |
| `--delegation-ttl` | Validity of each `W→K` delegation (default 16h; re-signed on reconnect). |
| `--insecure-tls` / `--no-p2p-bootstrap` | As in `attach`. |

## `mosey control`

Out-of-band admin commands. Every subcommand takes the same auth
flags as `attach` (because each one opens its own control stream).

| Subcommand | What it does | Caps required |
|---|---|---|
| `list-clients ENDPOINT` | Print the table of currently-attached clients. | none |
| `promote ENDPOINT ID` | Give client `ID` write permission. In `primary-observer`, makes them the writer seat. | Owner |
| `kick ENDPOINT ID` | Forcibly disconnect client `ID`. | Owner |
| `demote ENDPOINT` | Drop your own write + resize permissions. Useful for "going AFK." | none |
| `set-mode ENDPOINT MODE` | Switch multi-client mode at runtime. Applies to future attaches. | Owner |

`list-clients` writes a tab-separated table:

```
ID  LABEL   WRITE  COLSxROWS
1   owner   yes    160x52
2   reader  no     120x36
```

The IDs are stable within a vterm session's lifetime and not reused
after disconnect.

## `mosey cert`

Workspace-master and cert-minting tools. Lives in the same binary
because every host that runs `launch` / `attach` already has it.

| Subcommand | Output |
|---|---|
| `mint-master --out=DIR` | Generates a fresh BIP-39 master keypair. Writes `master.pub` + `master.key` to DIR; prints the mnemonic to stdout. **Record the mnemonic somewhere durable** — losing it means no more cert minting or revocation. |
| `mint-agent --master-key=... --workspace=... --label=... --caps=... --valid-for=... --out=...` | Mints a per-agent cert + keypair. `--caps` is a comma list of `owner`, `write`, `resize`. |
| `revoke --revocation-file=PATH --serial=SERIAL` | Appends `SERIAL` to PATH. Sending SIGHUP to the running `launch` makes it pick the new entry up. |

See [auth](auth.md) for the trust model.
