# multiscan-sast

SAST scaffold: `structural_hash` only in v1 — **no rules** (spec §7.5, NG-2).

## What v1 ships

- The crate skeleton with an `Engine` impl that always reports `NotApplicable`.
- `structural_hash` — the canonical hash that `multiscan-dedup` needs for the `StructuralPattern` identity (spec §7.7.2).

That's it, deliberately. **Do not add detection rules here in v1**, and taint analysis is *permanently* out of scope (NG-2) — structural matching is the ceiling. tree-sitter parsing and rule evaluation arrive with v2.

## `structural_hash`

Hashes the *shape* of a code fragment — its tree-sitter node kinds plus normalized identifiers — never raw line numbers or literal text. Two fragments differing only in whitespace, line position, or identifier spelling produce the same hash, so a `StructuralPattern` Finding stays stable across cosmetic edits.

The blake3 domain separator (`multiscan:structural_hash:v1`) is **frozen**: bumping it changes every `StructuralPattern` finding_id and invalidates user baselines. Changing it is a stop-and-ask event, same as any identity change.

Normative reference: `MULTISCAN-SDD-v1.0.md` §7.5.
