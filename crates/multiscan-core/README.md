# multiscan-core

Core generated types: `Finding`, `Asset`, `Severity`, `Confidence`, IDs. **Pure — no I/O** (spec §5.2).

This crate is the shared vocabulary of the whole workspace. Every engine, the dedup and risk crates, the store, and every renderer speak in these types.

## Generated, not written

Every type in `src/generated.rs` is produced from `schemas/*.json` by:

```sh
cargo xtask gen
```

Never edit `generated.rs` by hand — edit the schema and regenerate. CI byte-compares the output (`gen --check`), so drift fails the build. Hand-written behaviour lives in sibling modules as `impl` blocks on the generated types.

## Invariants

- **Zero I/O dependencies.** No tokio, no reqwest, no `std::fs`, no `SystemTime`. Enforced by the purity gate in CI.
- `#![forbid(unsafe_code)]`.
- `NetworkImpact` has exactly two variants — `ReadOnly` and `ActiveSafe`. There is no `Destructive` and there never will be; the type system is how NG-1 (never harm a target) is enforced.

## Making a change

1. Edit the relevant file under `schemas/`.
2. Run `cargo xtask gen`.
3. Fix whatever downstream code the new types break.

Schema changes that alter `finding_id` construction or serialized output are release-blocking events — see the spec before attempting one.

Normative reference: `MULTISCAN-SDD-v1.0.md` §5.
