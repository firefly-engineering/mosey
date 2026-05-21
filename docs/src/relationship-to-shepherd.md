# Relationship to shepherd

mosey is an extraction from
[shepherd](https://github.com/firefly-engineering/shepherd), the
Firefly Engineering control plane for AI coding agents. The pieces
in `internal/transport/`, `internal/auth/`, `internal/vterm/`, and
`internal/streambuf/` all originated as shepherd internals.

## Why split it out?

Shepherd's daemon-to-agent attach layer kept growing primitives
that had nothing to do with agent orchestration: multi-client modes,
HTTP/2 fallback, BIP-39 master keys, reattach-with-replay. None of
them depend on shepherd's session model, work-queue, or UI.

Splitting them into a separate module gives both projects clearer
ownership:

- **mosey** owns the wire protocols, the transport plumbing, and
  the multi-client / replay semantics. It's the thing that ships
  protocol IDs (`/ship/auth/1.0.0` and friends), and the thing
  that decides what "attach" means.
- **shepherd** consumes mosey as a library. Its
  `internal/streamagent` and `internal/agentrpc` packages dial
  `/ship/pty/` to bridge a shepherd-managed process to a remote
  shepherd user. Shepherd owns the workspace-membership story,
  the resumable session ID model, and the persistent state.

## Protocol IDs

The protocol identifiers are spelled `/ship/...` even though the
binary is `mosey`. They were minted while the project was named
`ship`; renaming them would invalidate every workspace master ever
generated (the HKDF context labels `ship-cert-v1` and
`ship-cert-master` are baked into key derivation). They're stable
wire identifiers, not branding.

## What shepherd will pull from mosey

In its current form, shepherd vendors a copy of these primitives.
The migration path is to swap the vendored copy for a direct
dependency on `github.com/firefly-engineering/mosey` once the
v0.1 surface is stable enough to commit to.

Specifically, shepherd needs:

- `transport.Transport` + libp2p backend for cross-host attaches.
- `auth.Wrap` + cert authenticator for workspace membership.
- `vterm.Session` for the agent-side process under PTY.
- `attach.Run` for the shepherd-side client.
- `cert.NewMasterMnemonic` for shepherd's workspace invite flow.

What stays in shepherd:

- Session ID model (mosey is stateless; shepherd is the durable
  store).
- Workspace ACLs (mosey has caps; shepherd has membership rules
  on top).
- Daemon process supervision, work queue, UI.

## Why duplicate `ship` vs `mosey`?

For one v0.1 cycle there are two names floating around: the binary
(`mosey`), and the wire vocabulary (`ship`). Operationally:

- Anything a user types: `mosey`.
- Anything that travels over the wire: `ship`.

Future versions might consolidate (a v2.0.0 of the protocols could
spell themselves `/mosey/...`), but pre-v0.1 it's not worth the
churn.
