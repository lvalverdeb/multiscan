# ADR 0011: Amend SEC-104 — git-history scanning is `--history` over all reachable objects

- Status: Accepted
- Date: 2026-08-06
- Amends: `MULTISCAN-SDD-v1.0.md` SEC-104 (§7.2). Supersedes the
  `--scan-history` + mandatory-commit-range wording. Realized by ADR 0006.

## Context

SEC-104 specified opt-in git-history secrets scanning via `--scan-history`
with an explicit commit range. ADR 0006 shipped history scanning as
`--history`, scanning every object reachable from any ref
(`git rev-list --objects --all`) with no required range. Two divergences: the
flag name and the scope. Per CLAUDE.md, spec and code disagreeing means the
code is wrong "unless an ADR in `docs/adr/` says otherwise" — this is that ADR.

## Decision

**Scope: all reachable objects by default, not a mandatory range.** The threat
SEC-104 exists to counter is "a secret committed and later removed is still
live in every clone's object store." The operator generally does *not* know
*when* it was committed — that ignorance is the whole reason to scan history.
A mandatory commit range would force them to guess where to look and would
**silently miss** secrets outside the guessed range: a security regression in
a control whose entire purpose is to catch what a working-tree scan cannot.
Scanning all reachable objects is the security-correct default. Volume is
bounded by ADR 0006's hard caps (20k blobs, 8 MiB/blob, 256 MiB total) with an
honest `Partial` outcome (exit 3) on truncation, so an explicit range is not
needed as a *requirement* — only, at most, as an optional performance selector.

**Flag: `--history` on `scan`.** Shorter, and consistent with `explain
--history`. The two live on different subcommands with distinct, documented
meanings (`scan --history` = git-history blobs; `explain --history` = a
finding's append-only audit trail); they do not collide in practice.
`--scan-history` was never shipped, and renaming a released flag would break
users for no security benefit.

## Amended requirement

> **SEC-104** Git history scanning is opt-in (`--history`) and, by default,
> scans every object reachable from any ref — a committed-then-removed secret
> may reside in any commit. It is bounded by hard blob/size caps and degrades
> to `Partial` on truncation (ADR 0006). An explicit commit-range or `--since`
> selector is a permitted future refinement, not a requirement.

## Consequences

- The SDD text of SEC-104 is updated to this form with an inline pointer to
  this ADR (normative requirements should read true; cf. §13.3, which this
  session made the point of enforcing).
- The opt-in property, provenance-in-evidence, identity-merge, and
  `Partial`-on-cap behavior from ADR 0006 are unchanged and remain normative.
- Out of scope, deferred: an optional range/`--since` selector; scanning
  unreachable (dangling) objects (already out of scope in ADR 0006).
