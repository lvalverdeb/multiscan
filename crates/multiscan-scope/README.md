# multiscan-scope

`ScopeAuthorization` verification, target resolution guard, and rate control (spec §9).

**This is the highest-scrutiny crate in the workspace.** Every request to a scan target — every one, anywhere in the product — goes through this crate (SEC-001..009). No bare `reqwest::get`, no direct `TcpStream` exists outside it. Feed downloads are the single separately allow-listed path, in `multiscan-feeds`.

## The two-stage gate

Hard-ordered and type-enforced — no code path can produce a connection without a passing decision, and every deny runs with **zero network I/O**:

1. **Static gate** — `Authorization::verify` → `VerifiedAuthorization`. Parse, signature, validity window, attestation, wildcard safety, and the per-request host+method check. All lexical: `evil.com` is ruled out of scope without ever being resolved.
2. **Connect-time gate** — `VerifiedAuthorization` + `resolve_pinned`. Resolve once, reject reserved/internal/rebinding IPs, and pin the exact `SocketAddr`s to dial (SEC-004). The connection must dial one of those pinned addresses — this is the DNS-rebinding defence.

`VerifiedAuthorization` is the *only* capability that unlocks resolution; it has no other constructor. `multiscan-probe` consumes it per hop, so out-of-scope redirects are denied by construction (SEC-005).

## Modules

`authorization` (parse/sign/verify) · `decision` (`Decision`, `Denied`) · `net` (IP allow rules) · `ratelimit` (`RateControl`, `Permit`) · `audit` (`AuditLog`) · `scope`.

The resolver is injectable (`Resolver`) so tests never touch real DNS.

## Rules for changing this crate

- `cargo xtask safety` (negative authorization tests) and `cargo xtask determinism` are **mandatory before any push** touching this crate.
- Never add a flag, env var, or config key that relaxes authorization — reviewers must reject these outright (SEC-009).
- Never point a test at a real host. `testdata/lab/` fixtures or recorded responses only.

Normative reference: `MULTISCAN-SDD-v1.0.md` §9.
