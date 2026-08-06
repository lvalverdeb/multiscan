# Architecture Decision Records

Each ADR records a deliberate decision that deviates from or extends
[`MULTISCAN-SDD-v1.0.md`](../../MULTISCAN-SDD-v1.0.md). Per the spec's rules of
engagement, when spec and code disagree the code is wrong **unless an ADR here
says otherwise** — so this directory is the authoritative record of sanctioned
deviations and amendments. Keep entries append-only; supersede rather than
rewrite.

| ADR | Title | Status | Relationship to the SDD |
|---|---|---|---|
| [0001](0001-msrv-1.85.md) | Raise MSRV from 1.78 to 1.85 | Accepted | Deviates from the front-matter MSRV |
| [0002](0002-scope-authorization-key-management.md) | Scope authorization key management (fail-closed, provided trusted key) | Accepted | Refines §9 authorization |
| [0003](0003-rename-cli-crate-to-multiscan.md) | Rename the CLI crate from `multiscan-cli` to `multiscan` | Accepted | Deviates from §5 workspace layout |
| [0004](0004-per-layer-exclude-sections.md) | Per-layer `[scan.<layer>]` exclude sections | Accepted | Extends §4.5 config |
| [0005](0005-entropy-known-noise.md) | Known-noise handling for the entropy fallback | Accepted | Extends §7.2; realizes FP-001/FP-002 (§13.3) |
| [0006](0006-git-history-secrets.md) | Opt-in git-history scanning in the secrets engine | Accepted | Extends §7.2 (see also ADR 0011) |
| [0007](0007-dockerfile-iac-checks.md) | Dockerfile checks in the IaC engine | Accepted | Extends §7.3 |
| [0008](0008-scoped-suppressions.md) | Rule- and path-scoped suppressions | Accepted | Extends §4.5 / CLI-006; realizes FP-003 |
| [0009](0009-ignore-files.md) | Ignore-file support (`.multiscanignore`, opt-in `.gitignore`) | Accepted | Extends §4.5 / §7 discovery; realizes FP-005 |
| [0010](0010-rule-pack-distribution.md) | Rule-pack distribution through the feed channel | Accepted | Extends §7.2/§10 (secrets, IaC, probe packs) |
| [0011](0011-history-flag-amends-sec-104.md) | Amend SEC-104 — `--history` over all reachable objects | Accepted | **Amends** SEC-104 (§7.2) |

## Conventions

- Filename: `NNNN-kebab-title.md`, zero-padded, sequential.
- Front-matter: `Status` (Accepted / Superseded / Proposed) and a
  `Deviates from` / `Extends` / `Amends` line naming the SDD section or
  requirement.
- An ADR that changes a **normative requirement** (e.g. ADR 0011 → SEC-104)
  also updates the requirement's text in the SDD with an inline
  `(Amended by ADR NNNN …)` pointer, so the normative document reads true.
