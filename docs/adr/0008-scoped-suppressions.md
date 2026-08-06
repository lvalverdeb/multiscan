# ADR 0008: Rule- and path-scoped suppressions

- Status: Accepted
- Date: 2026-08-06
- Extends: `MULTISCAN-SDD-v1.0.md` §4.5 and CLI-006, where a `[[suppress]]`
  entry selects a single `finding_id`. Adds two more selectors; the mandatory
  justification/approver/expires and the "no permanent suppression" rule are
  unchanged.

## Context

`finding_id`-only suppression does not scale to a *class* of finding. The
motivating case: 1,586 `high-entropy-string` findings in one `uv.lock` would
need 1,586 individual entries; the only alternative was a baseline file, which
grandfathers *everything* — including real findings present at snapshot time.
A reviewer cannot approve "these checksums are not secrets" in one line.

## Decision

A `[[suppress]]` entry gains two optional selectors alongside `finding_id`:

- `rule_id` — matches a finding whose engine rule/policy/template id (any
  `sources[].rule_id`) equals this value.
- `path` — a glob over the finding's root-relative POSIX `location.path`.

Rules:

- **At least one selector is required.** An entry with none would suppress
  everything; it is a config error (exit 2).
- **Present selectors are ANDed.** `rule_id = "high-entropy-string"` +
  `path = "uv.lock"` silences exactly that class in exactly that file.
- **CLI-006 is untouched.** justification, approver, and expires stay
  mandatory (enforced by the schema); an expired entry simply stops matching,
  so the finding gates again (FR-014).
- Globs compile at config resolution; a bad glob is a config error (exit 2),
  reported before any scanning — never a mid-scan failure.

Scoped selectors live only in the committed `multiscan.toml` (CLI-007:
diff-friendly, reviewable), not in the store. `multiscan suppress add` and the
SQLite store remain `finding_id`-only — a runtime acknowledgement of one
specific finding is a different act from a reviewed, committed policy.

## Consequences

- The 1,586-finding case becomes one reviewed, expiring entry.
- Suppression is still an explicit allowlist with an owner and an expiry; it
  never hides *new* findings outside its selectors, unlike a baseline.
- `rule_id` matches on `sources[].rule_id`, the uniform engine rule id;
  advisory ids and finding-class identity keys are matched via `finding_id`.
