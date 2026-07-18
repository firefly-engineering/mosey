# mosey

Domain glossary for mosey — a remote PTY attach system with pluggable
transports and pluggable authentication. This file is the project's ubiquitous
language: term definitions only, no implementation detail.

## Capabilities

**Caps**:
The permission bitmask a peer holds over a session — some combination of Write,
Resize, and Forge. Deliberately does *not* include ownership; an owner is a
structural fact that implies the full cap set.
_Avoid_: permissions, rights, scopes, capability bits (when you mean the type).

**Write / Resize / Forge**:
The three caps. Write: may send input to the PTY. Resize: may change the PTY
geometry. Forge: may sign further off-chain delegations rooted at this grant.
_Avoid_: type/input (for Write), resize-perm.

**Owner**:
A peer with full control of a session — mode switching, client management, and
implicitly every Cap. Ownership is structural (who the session belongs to), not
a Cap bit; it travels alongside Caps rather than inside the bitmask.
_Avoid_: admin, root, superuser.

**Grant**:
The result of resolving a peer's authority: an Owner flag paired with a Caps
set. What an Authenticator produces and what enforcement reads.
_Avoid_: permission set, ACL entry.

## Auth

**Authenticator**:
The pluggable credential model that runs the handshake and yields an Identity.
Three exist: PSK, workspace cert, and wallet delegation.
_Avoid_: auth provider, credential handler.

**Identity**:
The auth-layer result of a successful handshake — a Label plus the peer's Grant
(Owner + Caps). The zero value means unauthenticated.
_Avoid_: principal, user, subject.

**Delegation**:
A signed statement that attenuates authority from one wallet to another for a
session — the wallet-auth building block folded into a chain to compute Caps.
_Avoid_: grant (reserve that for the resolved Owner+Caps result), token.

## Transport

**Stream**:
One bidirectional byte channel between two peers, handed out by a Transport
backend (libp2p mux stream, HTTP/2 stream, WebSocket, unix socket). The unit the
auth wrap, vterm, and attach client program against — never a specific backend.
_Avoid_: connection, channel, socket.

**CorrelationID**:
An unauthenticated, per-dialer-instance handle a Stream carries so the auth wrap
can *link* streams — recognise that a later application stream comes from the
same party as an earlier auth-handshake stream. Stable for the dialer's lifetime
and identical across every stream that dialer opens (granularity: one client
process). It only *links* streams to an Identity the handshake already
established; it never itself *grants* identity. Empty when a backend cannot
correlate.
_Avoid_: session, session id, peer id, auth token, RemoteID.

**RemoteID**:
A backend-specific, human-facing identifier for the remote peer (libp2p peer id,
remote address, TLS subject) used only for log tagging. May be empty. Explicitly
*not* an authentication or correlation input — that job belongs to CorrelationID.
_Avoid_: correlation id, peer key, identity.
