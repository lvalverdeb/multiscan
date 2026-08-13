# Finding identity migrations

`finding_id` is derived from an identity tuple (spec §7.7.2), and a `Baseline`
or a `finding_id`-scoped `Suppression` is a reference to one. A change to how
the tuple is built therefore breaks those references: the same weakness, still
present, arrives under a new id and reads as new.

Identity changes are rare by design and each one is recorded here with the
population it moved and what to do about it. Stored findings are never
rewritten — history keeps the ids it was written with.

---

## Canonical vulnerability id widens past `aliases` — ADR 0023

**Landed:** unreleased (with ADR 0022). **Decided by:** ADR 0023, amending
§7.7.2. **Affects:** `VulnerableDependency` and `ContainerVulnerability`.

### What changed

The canonical vulnerability id in both tuples was the smallest CVE in the
advisory's `aliases`, else the advisory's own id. It is now the smallest CVE
in `aliases`, else in `upstream`, else in `related`, else the advisory's own
id.

The reason is that distro advisories almost never populate `aliases`: of 695
sampled openSUSE records, 674 name their CVE in `related` and none in
`aliases`. Distros also issue several advisory ids for one CVE in one package —
3,150 such `(ecosystem, package, CVE)` triples in AlmaLinux, 1,703 in openSUSE,
810 in Rocky Linux. Keyed on the advisory id, one weakness on one installed
package was reported two to five times; keyed on the CVE it merges into one
finding with every record in `sources[]`.

### Who is affected

**OS package findings (`ContainerVulnerability`): everyone, at no cost.**
Before ADR 0022 the feed layer mirrored no distro ecosystem, so no snapshot
could produce one of these findings at all. There is no history to invalidate.

**Dependency findings (`VulnerableDependency`): 61 advisory records.** Measured
against the mirrored ecosystems as of 2026-08-13, these records name no CVE in
`aliases` but do in `related`/`upstream`, so they moved from their own id to
the CVE:

| ecosystem | records |
|---|---|
| Packagist | 18 |
| PyPI | 10 |
| crates.io | 10 |
| Go | 9 |
| npm | 7 |
| Maven | 5 |
| RubyGems | 2 |
| NuGet | 0 |

Every other advisory — the overwhelming majority, which carry a CVE in
`aliases` — keys exactly as before. Precedence rather than a union is what
guarantees that: unioning the fields and taking the minimum would have re-keyed
a further 26 records to a CVE they never claimed to be.

### What to do

Nothing, unless a baseline or a `finding_id` suppression references one of the
61. In that case the finding re-appears as new on the next scan:

1. Re-run the scan and compare against the previous report. A finding whose
   `rule_id` matches a `PYSEC-…`/`GHSA-…` id you have baselined, now carrying a
   `CVE-…` identity, is one of these.
2. Refresh the baseline once you have confirmed the reappearing findings are
   the ones you already accepted — a baseline is a JSON Finding set, so
   `multiscan scan . --format json > .multiscan/baseline.json` rewrites it.
3. For `finding_id`-scoped suppressions, re-record the id. Rule- and
   path-scoped suppressions (ADR 0008) are unaffected — they never referenced
   an identity.

Scores are untouched: `formula_version` does not move, because the formula did
not change (`RSK-004`).
