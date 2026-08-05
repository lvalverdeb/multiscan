# multiscan-store

`Store` trait and SQLite implementation: baselines, history, suppressions (spec §11).

## Design

- **The `Store` trait is the seam for a future server backend** (P-8, STO-005). No SQLite type appears in its signatures — swapping the backend is a new impl, not a rewrite. `MemoryStore` exists for tests; `SqliteStore` is production.
- **History is event-sourced.** Status and score changes append, never overwrite (STO-002), so `multiscan history <id>` can reconstruct a Finding's full timeline.
- **Forward-compat refusal.** A database written by a newer binary is refused with `StoreError::SchemaTooNew` rather than opened and risked (STO-004).
- **Only a `Complete` engine outcome may close findings.** A `Partial` Scan must not mark unseen Findings resolved — the engine may simply not have gotten to them (§7.7.4, FR-015).

## What lives here

- Upserts from a Scan, with `UpsertStats` (new / seen-again / closed counts).
- Baselines for delta gating (`--baseline`): fail CI only on Findings newer than the baseline.
- Suppressions with reason and expiry.
- Append-only status/score history.

Time is passed in as `DateTime<Utc>` arguments — the store records events, it does not read the clock for identity-relevant data.

Normative reference: `MULTISCAN-SDD-v1.0.md` §11.
