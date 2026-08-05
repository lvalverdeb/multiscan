# multiscan-bridge

Bridges: external scanner output importers (spec §7.6).

A Bridge normalizes another tool's report into the MultiScan `Finding` model so `multiscan import` (or `scan --import`) folds it into the same pipeline — same dedup, same risk scoring, same renderers.

## Supported formats

Generic SARIF 2.1.0, Trivy JSON, Semgrep JSON, Checkov, and ZAP (`Format` detection plus per-tool modules). Entry point: `import_sarif` and format-specific importers behind it.

## Rules

- **Provenance is preserved** (BRG-001): imported Findings record the external tool in `sources[].engine_id`.
- **Explicit severity maps only** (BRG-002): each importer declares how the tool's severities map to ours. Passthrough severity is forbidden, same as native engines (ENG-004).
- **Unknown native ids stay namespaced** (BRG-003): an unmapped rule id becomes `native:{tool}:{id}` and must **not** merge with anything — a made-up cross-tool equivalence is worse than a duplicate.
- **Cross-engine dedup is the payoff** (FR-004): identity is reconstructed exactly the way native engines build it, so importing a Trivy report of the same weakness merges with the native SCA Finding instead of duplicating it.

## Untrusted-input discipline

External reports are attacker-controllable input like everything else: bounded allocations, capped entry counts, and parse failures return `BridgeError::Parse` — they never panic. Importers that grow nontrivial parsing get a fuzz target.

## Testing

Golden fixtures per tool go in `testdata/corpus/bridge/`, including a merge case (import + native → one Finding) and a near-miss that must stay separate.

Normative reference: `MULTISCAN-SDD-v1.0.md` §7.6.
