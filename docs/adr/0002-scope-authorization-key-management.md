# ADR 0002: Scope authorization key management (fail-closed, provided trusted key)

- Status: Accepted
- Date: 2026-08-05
- Relates to: spec §9.1 (ScopeAuthorization `signature`), SEC-001, SEC-009, R-7, §17.

## Context

§9.1 defines a `signature` field on a ScopeAuthorization but does not specify a
trust root — where the verifying key comes from, or what happens when it is
absent. SEC-001 requires a "valid, signed, in-window" authorization before any
`scan web` packet; SEC-009 forbids any bypass. This is an R-7 ambiguity: we must
not guess a convenient default that weakens the gate.

## Decision (conservative, fail-closed)

- The authorization signature is `ed25519:<hex>` over a **length-prefixed,
  domain-separated canonical byte string** of the authorization content
  (`multiscan:scope-auth:v1`) — not re-serialized JSON, so signer and verifier
  cannot drift on key ordering or whitespace. A `sign → verify` round-trip test
  pins the two sides together.
- Verification requires an **explicitly-provided trusted public key**
  (`--authorization-key <hex>`). If the key is **absent, malformed, or does not
  verify**, the authorization is **denied** (exit 4). There is no "unsigned but
  allowed" path and no env/config bypass (SEC-009).
- The decision (allow or deny) and its deciding rule are written to an
  append-only audit log (SEC-008); if the log cannot be written, the guard
  **fails closed**.

## Open question (recorded for §17)

A full trust story — a keyring / trusted-issuers file, key rotation, and an
`authorize create/verify/show` UX — is deferred. Until then the operator must
supply the trusted key out of band. This is intentionally minimal and
fail-closed rather than a convenient-but-weaker default.

## Consequences

- `scan web` cannot succeed without both a signed authorization and the matching
  trusted key — the safest posture for a feature that sends requests to remote
  targets (NG-5, A-1).
- When the keyring lands, `verify()` keeps its signature: it already takes the
  trusted key as an argument, so the change is in how the CLI sources the key,
  not in the gate.
