# multiscan-engine

The `Engine` trait, `EngineManifest`, `FindingSink`, and the engine registry (spec §6).

Engines are built-in Rust detection modules. This crate defines the contract they all implement and the plumbing that runs them; the engines themselves live under `crates/engines/`.

## The contract

- `applicable()` must be **cheap** — no file reads, no network. It only inspects the `ScanContext`.
- `scan()` **streams** `RawFinding`s into the `FindingSink`; engines never collect a whole set in memory (NFR-003).
- Engines check `ctx.cancel` between units of work and honour `ctx.deadline`. Ctrl-C produces partial output, not a hang.
- Recoverable problems (a malformed lockfile, an unreadable file) degrade to `EngineOutcome::Partial` with a warning — they never abort the Scan.
- Engines never touch the store, config files, or stdout directly (ENG-003). Everything flows through `ScanContext` and the sink.
- Every manifest declares an explicit `severity_map`; inferred or passthrough severity is forbidden (ENG-004).

`ScanContext` is where time and feed data are injected — pure crates downstream never read a clock (DET-004) or the network.

## Modules

| Module | Contents |
|---|---|
| `lib.rs` | `Engine`, `ScanContext`, `FindingSink`, `EngineError`, `EngineOutcome`, `Applicability` |
| `registry` | `Registry`, `EngineRun` — parallel execution via rayon; emit order is meaningless, sorting happens at render time (DET-002) |
| `testkit` | Shared test helpers for engine crates |

## Adding an engine

See "Adding an engine" in the repository `CLAUDE.md` — new crate under `crates/engines/`, `#![forbid(unsafe_code)]`, ≥3 golden fixtures, a fuzz target if it parses untrusted input.

Normative reference: `MULTISCAN-SDD-v1.0.md` §6.
