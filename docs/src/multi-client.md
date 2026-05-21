# Multi-client modes

When more than one client attaches to a single vterm, the session
needs a policy: who can type, who can resize, what happens to old
clients when a new one shows up. mosey ships four such policies
(set via `mosey launch --mode=...` or `mosey control set-mode`).

The mode applies only to the **dynamic** layer — every client still
needs the underlying `Write` / `Resize` caps from auth. The mode
decides whether those caps are honored right now.

## `supersede` (default)

> _Latest writer wins. Older writers get kicked._

When a new client attaches with `Write`, every prior `Write`-bearing
client receives a clean disconnect on its PTY stream. Observers
(`Write`-less clients) are unaffected.

Best for: pair-debugging where the "driver" rotates and you don't
want to manually demote.

## `exclusive`

> _One writer at a time. Late arrivals bounce until the seat is free._

The first attacher with `Write` claims the writer seat. Subsequent
attachers with `Write` are refused at the session layer (their
stream is closed with an error message). Observers attach as
normal.

Best for: high-stakes ops where you absolutely don't want the
"second person logged in and started typing" scenario.

## `primary-observer`

> _One designated writer. Everyone else observes by default._

The first attacher with `Write` becomes the primary. Subsequent
attachers join as observers regardless of their cap set —
`mosey control promote ID` flips the seat to the new client (the
prior primary is demoted to observer; no auto-recovery if the
new primary disconnects).

Best for: presentations, teaching, blue-team incident response —
you want everyone watching the same shell but only one set of
hands on the keyboard.

## `multi-write`

> _Everyone who holds `Write` can type. Bytes interleave._

Every `Write`-bearing client's keystrokes flow into the PTY. There
is no coordination layer; bytes arrive in the order the kernel
schedules the writes (per-client locking serializes at byte
granularity, so a single keystroke isn't split, but two clients'
words can interleave).

Best for: deliberate co-pilot moments where both sides know they're
typing into the same buffer. **Not a CRDT** — don't expect sensible
results if two people race to type a command.

## Geometry under each mode

`min(cols)` × `min(rows)` across **writers only** is the PTY size
(see [design](design.md#geometry-the-mincols-rows-rule)). Observer
geometry is recorded but ignored. Consequence:

| Mode | Geometry contributors |
|---|---|
| `supersede` | The current single writer. |
| `exclusive` | The seat holder. |
| `primary-observer` | The seat holder. |
| `multi-write` | All connected writers. |

Resizing the local terminal in any mode where you hold `Write`
sends a `Resize` message; the vterm recomputes the minimum. If
your terminal is currently the smallest, your resize bumps the PTY
size up immediately. If you're not, the kernel doesn't see the
change until you become the bottleneck.

## Runtime switching

```sh
mosey control set-mode ENDPOINT exclusive
```

The new mode applies to **future** attaches. Existing clients keep
their current permissions — use `mosey control demote` /
`mosey control promote` / `mosey control kick` to shape the active
set.

Why not auto-rebalance? Because every alternative is wrong for some
deployment: silently dropping the second writer when switching to
`exclusive` would hide the cap from the operator; auto-promoting
everyone on `multi-write` would surprise readers who never agreed
to type. Explicit control commands beat implicit policy.
