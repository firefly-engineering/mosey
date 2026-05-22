# Reattach and replay

A flaky network shouldn't leave the user staring at a black-screen
TUI. mosey's reattach protocol lets a client drop its TCP / QUIC
connection, redial, and resume rendering as if nothing happened —
within the bounds of the server's output ring buffer.

## The ring

`streambuf.OutputRing` is a fixed-size byte ring with a
monotonic sequence counter. Every byte the child process emits
gets tagged with its sequence number on the way through.

Defaults: 1 MiB capacity, sequence numbers `uint64`. Old data is
overwritten by new — there's no spill to disk.

## First attach

```
Client                                      Server (vterm)
  │                                           │
  │ Dial(/mosey/pty/1.0.0)                     │
  │ ─────────────────────────────────────────▶│
  │                                           │ start streaming
  │ ◀────── live bytes (seq N, N+1, N+2…) ────│
  │ render locally; remember last_seq         │
```

The client tracks the last sequence it saw locally (decrypted +
written to the local TTY). It doesn't echo it back during normal
operation — it's only needed on reconnect.

## Reattach

```
Client                                      Server (vterm)
  │ <connection drops>                        │
  │                                           │
  │ Dial(/mosey/pty-resume/1.0.0)              │
  │ ─────────────────────────────────────────▶│
  │ varint(last_seq)                          │
  │ ─────────────────────────────────────────▶│
  │                                           │ look up last_seq in ring
  │                                           │ if present: replay from there
  │                                           │ if missing : send everything in ring
  │ ◀────── replay bytes (seq L+1, L+2…) ─────│
  │ ◀────── then live bytes ─────────────────│
  │ resume rendering                          │
```

The varint is the first thing the client writes to the new stream
— so the server knows what to send before any live byte arrives.

## What can go wrong

- **Ring overrun.** If the child produced more than ~1 MiB
  between the disconnect and the resume, `last_seq` is no longer
  in the ring. The server replays everything it _does_ have
  (which won't line up with what the client already rendered);
  the client's TUI sees garbled output and usually recovers on
  the next full-screen redraw. This is best-effort, not
  guaranteed.

- **Network failure during replay.** Same recovery path — the
  client redials with whatever `last_seq` it now has and tries
  again.

- **Server restarted between drop and resume.** A new vterm
  process has a new ring and no shared sequence space. The
  resume varint is meaningless; the server has nothing to replay.
  The client sees an error (the new vterm has no session for the
  attach to resume) and exits.

## Why not just retransmit everything?

A naive design would have the client request "everything from byte
0." That works for short sessions but explodes for long-lived
shells: imagine reattaching after eight hours to a `tail -f`. The
ring caps the cost — replay is bounded by the ring size, not the
session lifetime.

The other naive design — sending nothing, hoping the next redraw
fills the gap — works for most full-screen TUIs but fails for
output that doesn't redraw on its own (a build log mid-line, a
prompt waiting for input). Replay-with-bounded-history splits the
difference.

## Visibility from the client

`mosey attach` reconnects automatically. The local terminal stalls
during the reconnect window — usually under a second on a working
network — then resumes. There's no UI prompt; the user sees a
pause and then continued output.

If you need to know whether reattaches are happening (operations
dashboards), enable `--log-level=info`. The reconnect loop logs
`stream closed, retrying` and `resumed at seq=N`.
