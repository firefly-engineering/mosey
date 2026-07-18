# Stream correlation is a first-class seam, distinct from RemoteID

`auth.Wrap` runs its handshake on a separate `ProtoAuth` stream, stores the
resulting `Identity` in a map, and then must recognise later application streams
as belonging to the same party. It keyed that map on `transport.Stream.RemoteID()`
— a field whose own doc says "used for log tagging; not for authentication." To
satisfy this unnamed requirement, each backend quietly overloaded `RemoteID()`
with a correlation value: websocket mints a random 128-bit per-process token and
smuggles it through `Sec-WebSocket-Protocol`, unix returns `uid=N:pid=M` from
SO_PEERCRED, http2 uses `RemoteAddr`, libp2p uses the peer id. The interface
contradicted its use, and every new backend had to reverse-engineer what auth
needed of it.

We name the requirement instead of hiding it.

## Decision

- **Add `CorrelationID() string` to `transport.Stream`; keep `RemoteID()` for
  logging.** Two methods, each with one job. `CorrelationID()` carries the auth
  contract; `RemoteID()` reverts to the honest, possibly-empty, human-facing log
  tag its doc already claimed it was.

- **Correlation granularity is the dialer instance (one client process).** Two
  streams with equal, non-empty `CorrelationID()` are guaranteed to come from the
  same dialer, across as many connections as it opens. We rejected *per-connection*
  (what the review's "same peer, this connection" phrasing implied — but websocket
  deliberately correlates across connections, and tightening it would re-auth every
  application stream) and *per-cryptographic-identity* (circular: for 3 of 4
  backends the whole point of the handshake is that identity isn't known until
  after correlation has already linked the streams).

- **`CorrelationID` links; the handshake grants.** The handle is an
  *unauthenticated* linking key. It never itself confers identity — it only ties an
  application stream to an `Identity` the handshake already established. This is the
  contract line that keeps a linking token from being mistaken for a credential.

- **Fail closed on empty, at `auth.Wrap`.** `auth.Wrap` refuses to store an
  Identity under an empty key and refuses any application stream whose
  `CorrelationID()` is empty. "Cannot correlate ⇒ cannot authenticate" lives once,
  at the consumer, not scattered across four backends. Backends may still
  pre-refuse for their own reasons.

- **Unforgeability is a stated contract, per backend.** A backend may return a
  non-empty `CorrelationID` only if that value is unforgeable or unguessable within
  its trust domain: cryptographic (libp2p peer id), kernel-attested (unix
  SO_PEERCRED), or ≥128-bit random (websocket token). `RemoteAddr`-grade handles
  (http2) are the weakest rung and correlate only per-connection — acceptable, but
  future backends get a clear bar.

## Scope

Interface change only. **No wire or protocol change:** the websocket
`mosey-peer-<token>` subprotocol vehicle and the unix peercreds derivation stay
byte-identical; only where the value surfaces in Go moves (`RemoteID()` →
`CorrelationID()`). `auth.Wrap` rekeys its map. The backend tests that today
assert `RemoteID` stability/distinctness (`TestBackend_RemoteIDStableAcrossDials`
and friends) migrate to assert `CorrelationID`, since that is the property they
were always testing; `RemoteID` gets new, looser assertions.

## Consequences

- The `transport.Stream` interface stops contradicting its documented contract;
  new backends implement a named requirement instead of guessing one.
- Correlation policy — the empty-guard, the link-not-grant rule — sits at one
  seam (`auth.Wrap`) rather than being implied by four backends.
- **Known limitations, unchanged by this refactor and deferred:** the `auth.Wrap`
  identity map never evicts, so (a) a websocket/unix peer's identity persists for
  the wrapper's lifetime and (b) unix pid-reuse can let a recycled pid inherit a
  dead process's identity. These pre-date this change; naming correlation does not
  alter them. Map eviction is a separate decision.
