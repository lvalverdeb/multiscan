# multiscan-probe

Probe engine: declarative HTTP template execution against authorized web targets — limited DAST (spec §7.4).

## Scope-limited by design (NG-3)

This is not a general web attack framework, and never will be:

- **Templates are data** (PRB-001): request shape + response matchers in YAML. No crawling, no session management, no form inference, no scripting, no eval.
- **Every request passes `multiscan-scope` before it is sent** (PRB-002). `ScopedTransport` wraps the transport so the authorization check is structural, not a call-site convention — including on every redirect hop, which is how out-of-scope redirects are refused (SEC-005).
- **Only idempotent methods run** (PRB-003/PRB-004), under scope-enforced rate control. `NetworkImpact` for probe Findings is at most `ActiveSafe` — the type has no `Destructive` variant (NG-1).
- A match earns `Proven` confidence only when it captures a **redacted** request/response exchange as Evidence (PRB-005); redaction lives in the `redact` module.

## Layout

`template` (parse/validate packs) · `executor` (`execute`, `ProbeRun`, the `Transport` seam for tests) · `matcher` (`Response` matching) · `scoped` (`ScopedTransport`) · `redact`.

The built-in template pack ships embedded (`rules/builtin.yaml`), with a blake3 digest exposed for provenance (FD-006).

## Rules for changing this crate

- `cargo xtask safety` and `cargo xtask determinism` are **mandatory before any push** touching this engine.
- Never point a test at a real host — `testdata/lab/` fixtures or recorded responses only, no exceptions.
- Making the engine capable of non-idempotent requests is a stop-and-ask change, not a PR.

Normative reference: `MULTISCAN-SDD-v1.0.md` §7.4.
