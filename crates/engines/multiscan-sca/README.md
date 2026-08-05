# multiscan-sca

SCA engine: lockfiles and OS packages → purl → OSV resolution (spec §7.1).

## Detection model

Parse manifests and lockfiles → construct [package URLs](https://github.com/package-url/purl-spec) → resolve against the **pinned OSV snapshot** from `multiscan-feeds` → emit `VulnerableDependency` Findings with fix-version remediation. The engine authors no advisory knowledge of its own; a new CVE is a feed refresh, not a code change.

Container images are handled by the `image` module: layer extraction and OS package database parsing (dpkg, apk, rpm — including SQLite rpmdb).

## Version matching (SCA-002)

Naive string comparison is the classic SCA bug — `"1.10.0" < "1.9.0"` lexically. Each ecosystem gets its own ordering (`version::Scheme`): semver, PEP 440, Maven, RubyGems, and friends all differ on pre-release and epoch handling. Never compare versions as strings.

## Untrusted-input discipline

Lockfiles and image layers are attacker-controllable (SCA-005):

- Per-file read cap (`MAX_LOCKFILE_BYTES`, 64 MB) and tree-walk cap (`MAX_FILES_VISITED`).
- Tar extraction validates paths — absolute paths, `..`, and symlink escapes are rejected; decompressed size and entry counts are capped. `cargo fuzz run tar_extract` is release-blocking for image work.
- A malformed file degrades to a stderr warning and `EngineOutcome::Partial` — it never aborts the Scan.

## Testing

Golden fixtures per ecosystem belong in `testdata/corpus/sca/`; `cargo xtask golden` diffs them. Version-ordering edge cases (epochs, pre-releases) get table tests in `version`.

Normative reference: `MULTISCAN-SDD-v1.0.md` §7.1.
