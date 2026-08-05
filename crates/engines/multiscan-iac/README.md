# multiscan-iac

IaC engine: HCL/YAML/JSON normalization and policy evaluation (spec §7.3).

## Model

Parse Terraform HCL (`hcl_parse`) and Kubernetes YAML/JSON (`k8s_parse`) into **one normalized resource tree** (`Resource`/`Value`), then evaluate the bundled CIS-mapped policy pack against it. One evaluation engine, many input syntaxes — policies never care which format a resource came from.

## Rules are data (IAC-001)

Policies are declarative `Condition` trees loaded from JSON — no scripting, no eval. The CIS pack ships embedded in the binary (`rules/cis-core.json`, content-addressed for provenance, FD-006), so the iac layer needs zero network access (FD-007). Policy IDs map to compliance controls; an unmapped ID falls back to `native:iac:{id}` and must not merge with anything.

## Honest uncertainty (IAC-003)

Terraform interpolations often can't be resolved statically. An unresolved value degrades the Finding to `Heuristic` confidence rather than producing a silent pass — "we couldn't tell" must never look like "this is fine".

## Untrusted-input discipline

HCL and YAML are attacker-controllable: per-file cap 16 MB, tree-walk cap on files visited, bounded recursion in both parsers. Malformed files degrade to a warning and `EngineOutcome::Partial`.

## Testing

Golden fixtures go in `testdata/corpus/iac/` and must cover both syntaxes plus the near-miss configurations each policy must **not** flag.

Normative reference: `MULTISCAN-SDD-v1.0.md` §7.3.
