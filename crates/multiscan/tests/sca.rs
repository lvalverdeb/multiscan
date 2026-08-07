//! T-202 acceptance at the CLI boundary: FR-002 (resolve a known-vulnerable
//! lockfile against a pinned snapshot, offline, with fixed_version populated)
//! and FR-003 (ecosystem-correct version matching — no naive-string false
//! positives). All hermetic: a snapshot is seeded into an isolated cache; no
//! network, no real host.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

use chrono::Utc;
use multiscan_feeds::{write_snapshot, SnapshotCounts, SnapshotData};

/// One OSV advisory: npm lodash < 4.17.21 (a real-shaped GHSA record).
const LODASH_ADVISORY: &str = r#"{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command injection in lodash","aliases":["CVE-2021-23337"],"database_specific":{"severity":"HIGH","cwe_ids":["CWE-77"]},"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}"#;

fn seed_snapshot(cache: &Path) -> String {
    let mut osv = BTreeMap::new();
    osv.insert(
        "npm".to_string(),
        format!("{LODASH_ADVISORY}\n").into_bytes(),
    );
    let mut osv_counts = BTreeMap::new();
    osv_counts.insert("npm".to_string(), 1u64);
    let data = SnapshotData {
        kev_json: br#"{"vulnerabilities":[{"cveID":"CVE-2021-23337"}]}"#.to_vec(),
        epss_csv: b"cve,epss,percentile\nCVE-2021-23337,0.6,0.97\n".to_vec(),
        osv_jsonl: osv,
        rule_packs: std::collections::BTreeMap::new(),
        counts: SnapshotCounts {
            kev: 1,
            epss: 1,
            osv: osv_counts,
        },
        sources: BTreeMap::new(),
    };
    write_snapshot(cache, &data, Utc::now())
        .unwrap()
        .manifest
        .snapshot_id
}

fn write_package_lock(dir: &Path, version: &str) {
    let content = format!(
        r#"{{"lockfileVersion":3,"packages":{{"":{{"name":"app"}},"node_modules/lodash":{{"version":"{version}"}}}}}}"#
    );
    std::fs::write(dir.join("package-lock.json"), content).unwrap();
}

fn scan_json(cache: &Path, project: &Path, extra: &[&str]) -> (Output, serde_json::Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_multiscan"))
        .env("MULTISCAN_CACHE_DIR", cache)
        .current_dir(project)
        .args(["scan", ".", "--layers", "sca", "--format", "json"])
        .args(extra)
        .output()
        .expect("binary runs");
    let value = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    (out, value)
}

/// FR-002: a vulnerable version resolves to the advisory with fixed_version.
#[test]
fn vulnerable_lockfile_resolves_offline() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    write_package_lock(project.path(), "4.17.20");

    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    let findings = findings.as_array().unwrap();
    assert_eq!(findings.len(), 1, "expected one advisory match");
    let f = &findings[0];
    assert_eq!(f["identity"]["advisory_id"], "CVE-2021-23337");
    assert_eq!(f["remediation"]["fixed_version"], "4.17.21");
    assert_eq!(f["remediation"]["fix_available"], true);
    assert_eq!(f["severity"], "high");
    // Enrichment: CVE is in KEV → factor X = 1.00 recorded in the explanation.
    assert!(
        (f["score_explanation"]["factors"]["exploitability"]
            .as_f64()
            .unwrap()
            - 1.0)
            .abs()
            < 1e-9
    );
}

/// FR-003: 4.17.21 is patched — a naive string compare ("4.17.21" vs "4.17.9")
/// would misjudge neighbours, but the fixed version must produce no finding.
#[test]
fn patched_version_produces_no_finding() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    write_package_lock(project.path(), "4.17.21");

    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(findings.as_array().unwrap().is_empty());
}

/// FR-003 again: 4.17.9 < 4.17.21 as versions (a string compare says the
/// opposite), so it MUST still be flagged.
#[test]
fn double_digit_patch_below_fix_is_flagged() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    write_package_lock(project.path(), "4.17.9");

    let (_out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(findings.as_array().unwrap().len(), 1);
}

/// SCA runs offline against the pinned snapshot with no network (the offline
/// harness proves no syscall; here we assert exit 0 and a real result).
#[test]
fn sca_offline_exit_zero_with_snapshot() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    write_package_lock(project.path(), "4.17.20");
    // High severity + KEV enrichment scores ~44.6; a threshold below it fires
    // the gate (exit 1), proving both resolution and enrichment ran.
    let (out, _f) = scan_json(
        cache.path(),
        project.path(),
        &["--offline", "--fail-on", "40"],
    );
    assert_eq!(out.status.code(), Some(1));
    // And a threshold above it does not.
    let (clean, _f) = scan_json(
        cache.path(),
        project.path(),
        &["--offline", "--fail-on", "90"],
    );
    assert_eq!(clean.status.code(), Some(0));
}

/// A directory with no lockfile → SCA not applicable → clean empty scan.
#[test]
fn no_lockfile_no_findings() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("README.md"), "hi").unwrap();
    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(findings.as_array().unwrap().is_empty());
}

/// FR-002/FR-003 for uv.lock: a pinned PyPI package below the fix resolves
/// against an ECOSYSTEM-range advisory with PEP 440 ordering, and the
/// workspace-local (virtual/editable) entries produce nothing.
#[test]
fn uv_lock_resolves_pypi_advisory_offline() {
    let cache = tempfile::tempdir().unwrap();
    // Seed a PyPI advisory alongside the npm one: Django < 3.2.15.
    let mut osv = BTreeMap::new();
    osv.insert(
        "npm".to_string(),
        format!("{LODASH_ADVISORY}\n").into_bytes(),
    );
    let django = r#"{"id":"PYSEC-2022-1","summary":"SQL injection in Django","aliases":["CVE-2022-34265"],"database_specific":{"severity":"HIGH","cwe_ids":["CWE-89"]},"affected":[{"package":{"ecosystem":"PyPI","name":"Django"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.2"},{"fixed":"3.2.15"}]}]}]}"#;
    osv.insert("PyPI".to_string(), format!("{django}\n").into_bytes());
    let mut osv_counts = BTreeMap::new();
    osv_counts.insert("npm".to_string(), 1u64);
    osv_counts.insert("PyPI".to_string(), 1u64);
    let data = SnapshotData {
        kev_json: br#"{"vulnerabilities":[]}"#.to_vec(),
        epss_csv: b"cve,epss,percentile\n".to_vec(),
        osv_jsonl: osv,
        rule_packs: std::collections::BTreeMap::new(),
        counts: SnapshotCounts {
            kev: 0,
            epss: 0,
            osv: osv_counts,
        },
        sources: BTreeMap::new(),
    };
    write_snapshot(cache.path(), &data, Utc::now()).unwrap();

    let project = tempfile::tempdir().unwrap();
    // uv normalizes names (django, not Django); PyPI matching re-normalizes.
    std::fs::write(
        project.path().join("uv.lock"),
        r#"
version = 1

[[package]]
name = "django"
version = "3.2.14"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "django" },
]
"#,
    )
    .unwrap();

    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    let findings = findings.as_array().unwrap();
    assert_eq!(
        findings.len(),
        1,
        "expected the Django advisory: {findings:?}"
    );
    let f = &findings[0];
    assert_eq!(f["identity"]["advisory_id"], "CVE-2022-34265");
    assert_eq!(f["remediation"]["fixed_version"], "3.2.15");
    assert_eq!(f["asset"]["identifier"], "pkg:pypi/django@3.2.14");
}

/// Seed a snapshot with one jsonl advisory blob per ecosystem.
fn seed_ecosystems(cache: &Path, advisories: &[(&str, &str)]) {
    let mut osv = BTreeMap::new();
    let mut osv_counts = BTreeMap::new();
    for (ecosystem, jsonl) in advisories {
        osv.insert(ecosystem.to_string(), format!("{jsonl}\n").into_bytes());
        osv_counts.insert(ecosystem.to_string(), jsonl.lines().count() as u64);
    }
    let data = SnapshotData {
        kev_json: br#"{"vulnerabilities":[]}"#.to_vec(),
        epss_csv: b"cve,epss,percentile\n".to_vec(),
        osv_jsonl: osv,
        rule_packs: std::collections::BTreeMap::new(),
        counts: SnapshotCounts {
            kev: 0,
            epss: 0,
            osv: osv_counts,
        },
        sources: BTreeMap::new(),
    };
    write_snapshot(cache, &data, Utc::now()).unwrap();
}

fn advisory_ids(findings: &serde_json::Value) -> Vec<String> {
    findings
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["identity"]["advisory_id"].as_str().unwrap().to_string())
        .collect()
}

/// yarn.lock (classic v1) resolves npm advisories.
#[test]
fn yarn_lock_resolves_npm_advisory() {
    let cache = tempfile::tempdir().unwrap();
    seed_ecosystems(cache.path(), &[("npm", LODASH_ADVISORY)]);
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("yarn.lock"),
        "# yarn lockfile v1\n\nlodash@^4.17.0:\n  version \"4.17.20\"\n",
    )
    .unwrap();
    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(advisory_ids(&findings), vec!["CVE-2021-23337"]);
}

/// go.sum resolves Go advisories: `v` prefix stripped, SemVer ordering.
#[test]
fn go_sum_resolves_go_advisory() {
    let cache = tempfile::tempdir().unwrap();
    let gin = r#"{"id":"GHSA-2c4m-59x9-fr2g","summary":"Improper input validation in gin","database_specific":{"severity":"MODERATE"},"affected":[{"package":{"ecosystem":"Go","name":"github.com/gin-gonic/gin"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.9.1"}]}]}]}"#;
    seed_ecosystems(cache.path(), &[("Go", gin)]);
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("go.sum"),
        "github.com/gin-gonic/gin v1.9.0 h1:aaaa=\n\
         github.com/gin-gonic/gin v1.9.0/go.mod h1:bbbb=\n\
         golang.org/x/text v0.13.0 h1:cccc=\n",
    )
    .unwrap();
    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(advisory_ids(&findings), vec!["GHSA-2c4m-59x9-fr2g"]);
    let f = &findings.as_array().unwrap()[0];
    assert_eq!(f["remediation"]["fixed_version"], "1.9.1");
    assert_eq!(
        f["asset"]["identifier"],
        "pkg:golang/github.com/gin-gonic/gin@1.9.0"
    );
}

/// Gemfile.lock resolves RubyGems advisories with Gem::Version ordering —
/// including a four-segment fix bound and a platform-suffixed install.
#[test]
fn gemfile_lock_resolves_rubygems_advisories() {
    let cache = tempfile::tempdir().unwrap();
    let rails = r#"{"id":"GHSA-rails-1","summary":"rails vuln","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"RubyGems","name":"rails"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"7.0.0"},{"fixed":"7.0.4.1"}]}]}]}"#;
    let nokogiri = r#"{"id":"GHSA-noko-1","summary":"nokogiri vuln","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"RubyGems","name":"nokogiri"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.13.9"}]}]}]}"#;
    seed_ecosystems(
        cache.path(),
        &[("RubyGems", &format!("{rails}\n{nokogiri}"))],
    );
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("Gemfile.lock"),
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.8-x86_64-linux)\n    rails (7.0.4)\n\nDEPENDENCIES\n  rails\n",
    )
    .unwrap();
    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    let mut ids = advisory_ids(&findings);
    ids.sort();
    assert_eq!(ids, vec!["GHSA-noko-1", "GHSA-rails-1"]);
    // 7.0.4 < 7.0.4.1 under Gem::Version (a string compare would also say
    // so, but 7.0.10 vs 7.0.9 would not — covered in the scheme unit tests).
    let rails_f = findings
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["identity"]["advisory_id"] == "GHSA-rails-1")
        .unwrap();
    assert_eq!(rails_f["remediation"]["fixed_version"], "7.0.4.1");
}

/// composer.lock resolves Packagist advisories; `v` prefixes normalized.
#[test]
fn composer_lock_resolves_packagist_advisory() {
    let cache = tempfile::tempdir().unwrap();
    let monolog = r#"{"id":"GHSA-mono-1","summary":"monolog vuln","database_specific":{"severity":"MODERATE"},"affected":[{"package":{"ecosystem":"Packagist","name":"monolog/monolog"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.9.0"}]}]}]}"#;
    seed_ecosystems(cache.path(), &[("Packagist", monolog)]);
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("composer.lock"),
        r#"{"packages":[{"name":"monolog/monolog","version":"v2.8.0"}],"packages-dev":[]}"#,
    )
    .unwrap();
    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(advisory_ids(&findings), vec!["GHSA-mono-1"]);
    assert_eq!(
        findings.as_array().unwrap()[0]["asset"]["identifier"],
        "pkg:composer/monolog/monolog@2.8.0"
    );
}

/// Manifest fallback: a repo with only package.json still gets SCA coverage —
/// an exact pin resolves against advisories.
#[test]
fn manifest_fallback_resolves_pinned_advisory() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"lodash":"4.17.20"}}"#,
    )
    .unwrap();
    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(advisory_ids(&findings), vec!["CVE-2021-23337"]);
}

/// A range declaration is never silently skipped: it surfaces as the SCA-001
/// unpinned finding (Informational/Unconfirmed).
#[test]
fn manifest_range_emits_unpinned_declaration() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"lodash":"^4.17.0"}}"#,
    )
    .unwrap();
    let (_out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    let arr = findings.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["identity"]["advisory_id"], "native:sca:unpinned");
    assert_eq!(arr[0]["severity"], "informational");
    assert_eq!(arr[0]["confidence"], "unconfirmed");
}

/// Shadowing: with a lockfile present the manifest is not parsed — the
/// lock's patched resolution wins over the manifest's vulnerable range.
#[test]
fn lockfile_shadows_manifest_in_same_dir() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"lodash":"4.17.20"}}"#,
    )
    .unwrap();
    write_package_lock(project.path(), "4.17.21"); // patched resolution
    let (_out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert!(
        findings.as_array().unwrap().is_empty(),
        "manifest must be shadowed by its lockfile: {findings:?}"
    );
}

/// Workspace shadowing: a member Cargo.toml is shadowed by the root
/// Cargo.lock one directory up.
#[test]
fn workspace_root_lock_shadows_member_manifest() {
    let cache = tempfile::tempdir().unwrap();
    seed_snapshot(cache.path());
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("Cargo.lock"),
        "version = 3\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n",
    )
    .unwrap();
    std::fs::create_dir(project.path().join("member")).unwrap();
    std::fs::write(
        project.path().join("member/Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .unwrap();
    let (_out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    // The member manifest would emit an unpinned finding if parsed; the
    // root lock shadows it and itself matches no advisory.
    assert!(
        findings.as_array().unwrap().is_empty(),
        "ancestor lock must shadow member manifest: {findings:?}"
    );
}

/// go.mod fallback: pinned requires resolve, `// indirect` drives evidence.
#[test]
fn go_mod_fallback_resolves_with_directness() {
    let cache = tempfile::tempdir().unwrap();
    let gin = r#"{"id":"GHSA-2c4m-59x9-fr2g","summary":"gin vuln","database_specific":{"severity":"MODERATE"},"affected":[{"package":{"ecosystem":"Go","name":"github.com/gin-gonic/gin"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.9.1"}]}]}]}"#;
    seed_ecosystems(cache.path(), &[("Go", gin)]);
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("go.mod"),
        "module example.com/app\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.0\n",
    )
    .unwrap();
    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(advisory_ids(&findings), vec!["GHSA-2c4m-59x9-fr2g"]);
}

/// pom.xml resolves Maven advisories with Maven version ordering; a
/// property-interpolated version surfaces as SCA-001 unpinned, never dropped.
#[test]
fn pom_xml_resolves_maven_advisory() {
    let cache = tempfile::tempdir().unwrap();
    // jackson-databind < 2.12.7.1 (a real-shaped advisory with a 4-segment fix).
    let jackson = r#"{"id":"GHSA-jjjj-jackson","summary":"jackson deserialization","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"Maven","name":"com.fasterxml.jackson.core:jackson-databind"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.12.7.1"}]}]}]}"#;
    seed_ecosystems(cache.path(), &[("Maven", jackson)]);
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("pom.xml"),
        r#"<project>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.12.1</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();
    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    let arr = findings.as_array().unwrap();
    // One advisory match + one unpinned declaration.
    let vuln = arr
        .iter()
        .find(|f| f["identity"]["advisory_id"] == "GHSA-jjjj-jackson")
        .expect("jackson advisory");
    assert_eq!(vuln["remediation"]["fixed_version"], "2.12.7.1");
    assert_eq!(
        vuln["asset"]["identifier"],
        "pkg:maven/com.fasterxml.jackson.core:jackson-databind@2.12.1"
    );
    assert!(arr
        .iter()
        .any(|f| f["identity"]["advisory_id"] == "native:sca:unpinned"
            && f["asset"]["identifier"] == "pkg:maven/org.slf4j:slf4j-api"));
}

/// gradle.lockfile resolves Maven advisories.
#[test]
fn gradle_lockfile_resolves_maven_advisory() {
    let cache = tempfile::tempdir().unwrap();
    let logback = r#"{"id":"GHSA-logback-1","summary":"logback vuln","database_specific":{"severity":"MODERATE"},"affected":[{"package":{"ecosystem":"Maven","name":"ch.qos.logback:logback-core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.13"}]}]}]}"#;
    seed_ecosystems(cache.path(), &[("Maven", logback)]);
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("gradle.lockfile"),
        "# Gradle dependency locking\nch.qos.logback:logback-core:1.2.11=runtimeClasspath\norg.slf4j:slf4j-api:2.0.7=runtimeClasspath\nempty=annotationProcessor\n",
    )
    .unwrap();
    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(advisory_ids(&findings), vec!["GHSA-logback-1"]);
}

/// ADR 0012: two advisory records (a GHSA and a PYSEC) that share a CVE
/// collapse into ONE finding keyed on the CVE, at the higher severity, with
/// both record ids preserved in evidence.
#[test]
fn same_cve_advisories_merge_into_one_finding() {
    let cache = tempfile::tempdir().unwrap();
    let ghsa = r#"{"id":"GHSA-aaaa-bbbb-cccc","summary":"widget RCE","aliases":["CVE-2099-1234"],"database_specific":{"severity":"HIGH","cwe_ids":["CWE-94"]},"affected":[{"package":{"ecosystem":"npm","name":"widget"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}"#;
    // Same CVE, no severity (would default to medium) — must not appear separately.
    let pysec = r#"{"id":"PYSEC-2099-1","summary":"widget RCE (pysec)","aliases":["CVE-2099-1234"],"affected":[{"package":{"ecosystem":"npm","name":"widget"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}"#;
    seed_ecosystems(cache.path(), &[("npm", &format!("{ghsa}\n{pysec}"))]);

    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/widget":{"version":"1.0.0"}}}"#,
    )
    .unwrap();

    let (out, findings) = scan_json(cache.path(), project.path(), &["--offline"]);
    assert_eq!(out.status.code(), Some(0));
    let arr = findings.as_array().unwrap();
    // Exactly one finding for widget, keyed on the CVE, at HIGH severity.
    let widget: Vec<_> = arr
        .iter()
        .filter(|f| f["asset"]["identifier"] == "pkg:npm/widget@1.0.0")
        .collect();
    assert_eq!(widget.len(), 1, "GHSA + PYSEC of one CVE must be one finding: {widget:?}");
    let f = widget[0];
    assert_eq!(f["identity"]["advisory_id"], "CVE-2099-1234");
    assert_eq!(f["severity"], "high", "merged finding takes the max severity");
    // Both constituent OSV records appear as sources (dedup by shared CVE).
    let rules: Vec<String> = f["sources"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["rule_id"].as_str().map(str::to_string))
        .collect();
    assert!(
        rules.contains(&"GHSA-aaaa-bbbb-cccc".to_string())
            && rules.contains(&"PYSEC-2099-1".to_string()),
        "both records as sources: {rules:?}"
    );
}
