# ADR 0003: Rename the CLI crate from `multiscan-cli` to `multiscan`

- Status: Accepted
- Date: 2026-08-05
- Deviates from: `MULTISCAN-SDD-v1.0.md` §5 workspace layout (`multiscan-cli/`)
  and T-105's deliverable wording.

## Context

The spec names the binary crate `multiscan-cli`, following the workspace's
`multiscan-<role>` pattern. The crate already built a binary named `multiscan`
via a `[[bin]]` override, so the discrepancy was invisible locally.

crates.io, however, reserves **package** names, not binary names. Publishing
the workspace as specced would claim `multiscan-core` … `multiscan-cli` while
leaving the product name `multiscan` unclaimed and squattable, and
`cargo install multiscan` — the first thing a new user tries — would fail.
Verified against the crates.io index on 2026-08-05: `multiscan` is unclaimed.

## Decision

Rename the package to `multiscan` (directory `crates/multiscan/`). The
`[[bin]]` override is dropped: package name plus `src/main.rs` yields the
`multiscan` binary automatically. `cargo install multiscan` works, and
publishing reserves the product name.

A separate placeholder crate was rejected: a binary cannot be re-exported
through a dependency, so a placeholder would be either an empty name-squat
(against crates.io policy) or a duplicate of the CLI.

## Consequences

- The Makefile publish order now uses full crate names; the CLI publishes
  last, as before.
- Spec references to `multiscan-cli` (layout §5, T-105) read as
  `crates/multiscan` under this ADR; the spec text itself is unchanged
  per R-7 discipline.
- No library crate depends on the binary crate, so no dependency or import
  changes anywhere.
