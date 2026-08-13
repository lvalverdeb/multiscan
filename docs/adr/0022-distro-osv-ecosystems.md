# ADR 0022: Mirror the distro OSV ecosystems, and match them on a normalized distro key

- Status: Accepted
- Date: 2026-08-13
- Extends: `MULTISCAN-SDD-v1.0.md` §10 (feeds) and §7.1 (SCA OS packages).
  Realizes `FR-002` on the default path for OS packages, which `T-402`
  delivered the parsers for but the feed layer never fed. No requirement text
  changes.

## Context

`T-402` shipped the OS package path end to end: `image/ospkg.rs` parses dpkg,
apk, and the sqlite rpmdb; `image/mod.rs` builds a purl per installed package,
looks the name up in the `OsvIndex`, and emits `ContainerVulnerability`
findings. The feed layer never followed. `FeedSources::default()` mirrors eight
ecosystems — `crates.io`, `npm`, `PyPI`, `Go`, `Maven`, `RubyGems`,
`Packagist`, `NuGet` — under a comment reading "OS package ecosystems join in
phase 4 with image scanning". Phase 4 shipped; the list did not change, and the
list is not reachable from config, CLI, or environment.

The consequence is not a partial result, it is a silent zero:
`OsvIndex::from_cache` builds its map from the `osv/*.jsonl` files a snapshot
carries, so on every snapshot `multiscan db update` has ever written,
`advisories_for("Debian:12", "xz-utils")` returns an empty slice. Image scans
report package counts and emit no OS package finding, for any CVE, on any
distro. The engine reports `Complete`, because from its side nothing failed.

Mirroring the missing ecosystems is necessary and not sufficient. Measured
against OSV on 2026-08-13, the ecosystem strings in the advisory records do not
match what `OsRelease::osv_ecosystem` constructs:

| distro | OSV `package.ecosystem` | what we construct |
|---|---|---|
| Debian | `Debian:12` | `Debian:12` ✔ |
| Alpine | `Alpine:v3.20` | `Alpine:v3.20` ✔ |
| Ubuntu | `Ubuntu:22.04:LTS`, `Ubuntu:23.10` | `Ubuntu:22.04` ✘ |
| Ubuntu Pro | `Ubuntu:Pro:22.04:LTS` | — |
| RHEL | `Red Hat:enterprise_linux:8::appstream` | `Red Hat` ✘ |
| openSUSE | `openSUSE:Tumbleweed`, `openSUSE:Leap 15.6` | — (`_ => None`) ✘ |
| SUSE | `SUSE:Linux Enterprise Server 15 SP4` | — ✘ |
| Rocky, Alma | `Rocky Linux:9`, `AlmaLinux:9` | same ✔ |
| Azure Linux, openEuler, Mageia | `Azure Linux:3`, `openEuler:24.03-LTS`, `Mageia:9` | — ✘ |
| Chainguard, Wolfi | `Chainguard`, `Wolfi` (unversioned) | — ✘ |

`Advisory::matches` compares `package.ecosystem` for exact equality, so Ubuntu
and RHEL — between them most of the installed base — would still match nothing
with a complete mirror in place. Fedora is not an OSV bucket at all: it does
not appear in `ecosystems.txt`, so the `Fedora:{v}` arm can never be served.

Three further facts shaped the decision:

- **Base-name buckets already contain every release.** `Alpine/all.zip` carries
  records for `Alpine:v3.2` through `Alpine:v3.22`; `Debian:12/all.zip`
  cross-lists `Debian:11` and `Debian:13` (and 2,090 `Alpine:*` entries).
  Release-qualified buckets are redundant, and half of them do not exist under
  the name we would guess — `Ubuntu:20.04` 404s, the bucket is
  `Ubuntu:20.04:LTS`.
- **Release-qualified names are not portable filenames.** `write_snapshot`
  stores `osv/<ecosystem>.jsonl`, and `osv/Ubuntu:22.04:LTS.jsonl` is not a
  valid name on NTFS (`NFR-007` includes windows-x86_64).
- **Eager loading does not survive this much data.** `OsvIndex::from_cache`
  parses every `osv/*.jsonl` in the snapshot into memory on every scan.
  Today's snapshot is ~515 MB of JSONL; the distro ecosystems add ~4 GB
  (zipped: Ubuntu 617 MB, Debian 71, SUSE 46, Chainguard 30, Red Hat 26,
  openSUSE 21, Wolfi 19, openEuler 16, Azure Linux 11, Mageia 6.4, AlmaLinux
  6.0, Rocky 4.6, Alpine 4.0; JSONL expands ≈ 4.7×). `NFR-003` caps peak RSS
  at 500 MB.

## Decision

1. **The default mirror set gains the distro base ecosystems**, Ubuntu
   included: `Debian`, `Ubuntu`, `Alpine`, `Red Hat`, `Rocky Linux`,
   `AlmaLinux`, `openSUSE`, `SUSE`, `Chainguard`, `Wolfi`, `Azure Linux`,
   `openEuler`, `Mageia`. `[feeds] osv_ecosystems` in `multiscan.toml`
   overrides the set, for operators who will not spend the disk.

2. **Base names only.** Ecosystem names carrying `:` are rejected by
   `write_snapshot` alongside `/`, `\`, and `..`, so a snapshot stays
   extractable on every `NFR-007` platform. The URL path segment is
   percent-encoded — three of the names contain a space.

3. **The index keys on the record's own `package.ecosystem`, not the file
   name.** A lookup for `Debian:12` therefore resolves inside `osv/Debian.jsonl`.
   Because base buckets cross-list, advisories are deduplicated by id within
   each `(ecosystem, name)` bucket at load time rather than left for the merge
   pass to hide.

4. **Only the records a scan can match are loaded** — the non-distro
   ecosystems for a lockfile scan, and for an image, the records for its
   detected release alone. Selecting the file is not enough: the `Ubuntu`
   bucket holds 14.04 through 24.04 plus every Pro variant, so a 22.04 scan
   that indexed the whole file would carry roughly ten times the advisories it
   can use. Both filters together are what keep `NFR-003` reachable with a
   4 GB snapshot on disk.

5. **Ecosystem matching is by normalized distro key.** One function pair maps
   an OSV ecosystem string and an `os-release` `(ID, VERSION_ID)` to the same
   `(distro, release)` tuple — `Ubuntu:22.04:LTS` and `ID=ubuntu
   VERSION_ID=22.04` both to `(ubuntu, 22.04)`. Exact string equality is tried
   first and still governs the lockfile ecosystems, which need no normalization.

6. **Ubuntu Pro is a distinct distro** (`ubuntu-pro`) and never matches a
   non-Pro release. Its records describe fixes available only under a Pro
   subscription; reporting one against a plain 22.04 image would advertise a
   `fixed_version` the user cannot install.

7. **Red Hat product qualifiers collapse to the OS release**:
   `Red Hat:enterprise_linux:8::appstream` → `(rhel, 8)`. The layered products
   in that same bucket — `openshift`, `ansible_automation_platform`,
   `ceph_storage` — are not an OS package inventory and map to no distro key.

8. **A per-ecosystem fetch or parse failure degrades, it does not abort.** One
   missing bucket must not cost the operator the other twelve. Skipped
   ecosystems are recorded in the snapshot manifest and printed by
   `multiscan db status`, not merely warned about on a stderr line that scrolls
   past — a snapshot that silently lacks an ecosystem reads exactly like one
   that found nothing in it.

9. **Fedora and Arch are documented gaps.** OSV publishes no Fedora bucket, and
   there is no pacman database parser. Both degrade to a stated
   `unsupported-distro` reason rather than an empty `Complete`.

10. **purls and identity are untouched.** Normalization is match-side only:
    `pkg:deb/debian/xz-utils@5.6.1-1` and
    `IdentityKey::ContainerVulnerability` are constructed exactly as before, so
    no existing `finding_id` moves.

## Consequences

- A default `multiscan db update` now downloads ~900 MB and stores ~4.5 GB.
  Ubuntu is ~3 GB of that; `[feeds] osv_ecosystems` is the documented way to
  drop it. `db status` prints per-ecosystem counts, so the cost is visible.
- OS package findings appear for the first time. Anyone scanning images against
  a policy gate will see their finding count rise on the first scan after the
  update — this is the requirement working, not a regression, but it is a
  reportable change for `FR-015` baselines.
- Distro advisories mostly do not carry their CVE in `aliases`, so these
  findings arrive keyed on the advisory id (`openSUSE-SU-2024:14017-1`) and
  without KEV/EPSS enrichment. ADR 0023 covers that separately.
- An air-gap bundle whose manifest carries release-qualified ecosystem files
  (`osv/Debian:12.jsonl`) now fails to import, with the name in the error.
  Nothing in the tool has ever produced such a bundle — only a hand-built one
  could carry it — and the reading path still tolerates the layout, so
  re-exporting from an updated cache is the migration.
- The golden corpus is unchanged — it contains no image with a matching
  advisory, so nothing in it moves. Coverage for this change is the
  normalization tests, which assert against ecosystem strings captured from
  the live buckets on 2026-08-13, and two CLI-boundary image tests (a Debian
  dpkg image, and a Wolfi apk image whose advisory carries its CVE in
  `related`). Distro-family golden fixtures are worth adding when the rpm
  path grows a sqlite `rpmdb` corpus fixture; the apk and dpkg databases are
  text and covered here.

## Rejected alternatives

- **Mirror release-qualified ecosystems** (`Debian:12`, `Ubuntu:22.04:LTS`, …).
  Produces snapshot filenames that are invalid on Windows, requires tracking
  every distro's release cadence in our default list, and buys nothing: the
  base buckets already contain the same records.
- **Prefix-match ecosystem strings in `matches()`** (`starts_with("Ubuntu:")`).
  Cheap and wrong: `Ubuntu:Pro:22.04:LTS` prefixes `Ubuntu:`, and
  `Red Hat:openshift:…` prefixes `Red Hat`. The failure mode is false positives
  in exactly the direction users trust least.
- **Leave distro data to `db import` bundles.** It works today and will keep
  working, but it makes `FR-002` an expert feature and leaves the default path
  reporting zero where the truth is unknown.
- **Query the OSV API for OS packages instead of mirroring.** `FD-003` says a
  scan never fetches; ADR 0020 confined API use to the explicit `--freshness`
  opt-in, and that path builds from lockfile inventory by design.
