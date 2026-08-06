//! Lockfile and manifest parsers (spec 7.1). Each produces a list of
//! [`ResolvedPackage`]s; parsing is defensive (untrusted input) and a
//! malformed file degrades to a warning + `Partial`, never an abort.

use serde::Deserialize;

/// A concrete package to resolve against OSV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPackage {
    /// OSV ecosystem string (e.g. `crates.io`, `npm`, `PyPI`).
    pub ecosystem: String,
    /// purl type (e.g. `cargo`, `npm`, `pypi`).
    pub purl_type: String,
    /// Package name.
    pub name: String,
    /// Exact resolved version. `None` for unpinned declarations (SCA-001).
    pub version: Option<String>,
    /// Whether this is a direct dependency (best-effort; drives evidence).
    pub direct: bool,
}

impl ResolvedPackage {
    /// The Package URL for this package (spec 7.7.2 identity input).
    pub fn purl(&self) -> String {
        match &self.version {
            Some(v) => format!("pkg:{}/{}@{}", self.purl_type, self.name, v),
            None => format!("pkg:{}/{}", self.purl_type, self.name),
        }
    }
}

/// A lockfile parser: text → resolved packages, or a degradation reason.
pub type ParseFn = fn(&str) -> Result<Vec<ResolvedPackage>, String>;

/// Which parser applies to a file name (cheap, name-only — no reads).
pub fn parser_for(file_name: &str) -> Option<ParseFn> {
    match file_name {
        "Cargo.lock" => Some(parse_cargo_lock),
        "package-lock.json" | "npm-shrinkwrap.json" => Some(parse_package_lock),
        "requirements.txt" => Some(parse_requirements_txt),
        "uv.lock" => Some(parse_uv_lock),
        "yarn.lock" => Some(parse_yarn_lock),
        "pnpm-lock.yaml" => Some(parse_pnpm_lock),
        "go.sum" => Some(parse_go_sum),
        "poetry.lock" => Some(parse_poetry_lock),
        "Gemfile.lock" => Some(parse_gemfile_lock),
        "composer.lock" => Some(parse_composer_lock),
        _ => None,
    }
}

/// File names this engine recognizes, for cheap applicability checks.
pub const SUPPORTED_FILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "requirements.txt",
    "uv.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.sum",
    "poetry.lock",
    "Gemfile.lock",
    "composer.lock",
];

// ---- Cargo.lock ----

#[derive(Deserialize)]
struct CargoLock {
    #[serde(default)]
    package: Vec<CargoPackage>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
}

fn parse_cargo_lock(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let lock: CargoLock = toml::from_str(text).map_err(|e| format!("Cargo.lock: {e}"))?;
    Ok(lock
        .package
        .into_iter()
        .map(|p| ResolvedPackage {
            ecosystem: "crates.io".to_string(),
            purl_type: "cargo".to_string(),
            name: p.name,
            version: Some(p.version),
            // Cargo.lock does not distinguish direct vs transitive; treat all
            // as resolvable, evidence marks them transitive-unknown.
            direct: false,
        })
        .collect())
}

// ---- package-lock.json (npm v2/v3 "packages" map, and legacy v1 "dependencies") ----

#[derive(Deserialize)]
struct PackageLock {
    #[serde(default)]
    packages: std::collections::BTreeMap<String, NpmPackage>,
    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, NpmLegacyDep>,
}

#[derive(Deserialize)]
struct NpmPackage {
    #[serde(default)]
    version: Option<String>,
}

#[derive(Deserialize)]
struct NpmLegacyDep {
    #[serde(default)]
    version: Option<String>,
}

fn parse_package_lock(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let lock: PackageLock =
        serde_json::from_str(text).map_err(|e| format!("package-lock.json: {e}"))?;
    let mut out = Vec::new();
    // npm v2/v3: keys are "node_modules/<name>" or "node_modules/a/node_modules/b".
    for (path, pkg) in &lock.packages {
        if path.is_empty() {
            continue; // the root project entry
        }
        let Some(name) = path.rsplit("node_modules/").next() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        // Direct deps live at top level: exactly "node_modules/<name>".
        let direct = path.matches("node_modules/").count() == 1;
        out.push(ResolvedPackage {
            ecosystem: "npm".to_string(),
            purl_type: "npm".to_string(),
            name: name.to_string(),
            version: pkg.version.clone(),
            direct,
        });
    }
    // Fallback for npm v1 lockfiles.
    if out.is_empty() {
        for (name, dep) in &lock.dependencies {
            out.push(ResolvedPackage {
                ecosystem: "npm".to_string(),
                purl_type: "npm".to_string(),
                name: name.clone(),
                version: dep.version.clone(),
                direct: true,
            });
        }
    }
    Ok(out)
}

// ---- uv.lock (uv's TOML workspace lockfile; [[package]] entries) ----

#[derive(Deserialize)]
struct UvLock {
    #[serde(default)]
    package: Vec<UvPackage>,
}

#[derive(Deserialize)]
struct UvPackage {
    name: String,
    #[serde(default)]
    version: Option<String>,
    /// Source table, e.g. `{ registry = "..." }`, `{ virtual = "." }`,
    /// `{ editable = "../member" }`, `{ git = "..." }`. Kept as a raw map so
    /// unknown future source kinds parse instead of failing the file.
    #[serde(default)]
    source: Option<std::collections::BTreeMap<String, toml::Value>>,
    #[serde(default)]
    dependencies: Vec<UvDependency>,
    #[serde(default, rename = "dev-dependencies")]
    dev_dependencies: std::collections::BTreeMap<String, Vec<UvDependency>>,
    #[serde(default, rename = "optional-dependencies")]
    optional_dependencies: std::collections::BTreeMap<String, Vec<UvDependency>>,
}

/// One entry of a `dependencies` array: `{ name = "idna", marker = "..." }`.
#[derive(Deserialize)]
struct UvDependency {
    name: String,
}

/// Workspace-local packages (`virtual`, `editable`, `directory`, `path`
/// sources) are the user's own code: they are not PyPI packages, and
/// resolving their names against PyPI advisories would invite name-collision
/// false positives. They are skipped from the inventory but their dependency
/// lists define what counts as a direct dependency.
fn uv_source_is_local(source: &Option<std::collections::BTreeMap<String, toml::Value>>) -> bool {
    source.as_ref().is_some_and(|s| {
        ["virtual", "editable", "directory", "path"]
            .iter()
            .any(|key| s.contains_key(*key))
    })
}

fn parse_uv_lock(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let lock: UvLock = toml::from_str(text).map_err(|e| format!("uv.lock: {e}"))?;

    // Direct = declared by any workspace-local package, in its runtime,
    // dev-group, or extras lists (best-effort; drives evidence only).
    let mut direct_names = std::collections::BTreeSet::new();
    for package in lock.package.iter().filter(|p| uv_source_is_local(&p.source)) {
        let groups = package
            .dev_dependencies
            .values()
            .chain(package.optional_dependencies.values());
        for dep in package.dependencies.iter().chain(groups.flatten()) {
            direct_names.insert(dep.name.clone());
        }
    }

    Ok(lock
        .package
        .into_iter()
        .filter(|p| !uv_source_is_local(&p.source))
        .map(|p| ResolvedPackage {
            ecosystem: "PyPI".to_string(),
            purl_type: "pypi".to_string(),
            direct: direct_names.contains(&p.name),
            // uv pins every resolved package; a missing version degrades to
            // an unpinned declaration (SCA-001) rather than being dropped.
            version: p.version,
            name: p.name,
        })
        .collect())
}

// ---- yarn.lock (classic v1 line format and Berry YAML) ----

/// `name` from a yarn descriptor: `lodash@^4.17.20`, `@babel/core@npm:^7.0`.
/// The name is everything before the last `@` (which is never at index 0 for
/// a valid descriptor — scoped names start with `@` but always contain one
/// more for the range).
fn yarn_key_name(key: &str) -> Option<String> {
    let at = key.rfind('@').filter(|&i| i > 0)?;
    Some(key[..at].to_string())
}

fn parse_yarn_lock(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    if text.contains("__metadata:") {
        return parse_yarn_berry(text);
    }
    // v1: unindented `key1, key2:` header lines, then indented fields; the
    // resolved version is on a `  version "x.y.z"` line.
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with([' ', '\t']) && line.trim_end().ends_with(':') {
            let first_key = line
                .trim_end()
                .trim_end_matches(':')
                .split(',')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"');
            current = yarn_key_name(first_key);
        } else if let Some(name) = current.clone() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("version") {
                let version = rest.trim().trim_matches('"');
                if !version.is_empty() {
                    out.push(ResolvedPackage {
                        ecosystem: "npm".to_string(),
                        purl_type: "npm".to_string(),
                        name,
                        version: Some(version.to_string()),
                        // yarn.lock does not mark direct deps (package.json does).
                        direct: false,
                    });
                }
                current = None;
            }
        }
    }
    Ok(out)
}

/// yarn Berry (v2+): the same file name, but YAML with an `__metadata` block
/// and `name@npm:range` descriptor keys. Workspace-local entries
/// (`name@workspace:.`) are the user's own packages and are skipped.
fn parse_yarn_berry(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(text).map_err(|e| format!("yarn.lock: {e}"))?;
    let Some(map) = doc.as_mapping() else {
        return Err("yarn.lock: not a mapping".to_string());
    };
    let mut out = Vec::new();
    for (key, value) in map {
        let Some(key) = key.as_str() else { continue };
        if key == "__metadata" || key.contains("@workspace:") {
            continue;
        }
        let Some(name) =
            yarn_key_name(key.split(',').next().unwrap_or("").trim().trim_matches('"'))
        else {
            continue;
        };
        let version = value
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        out.push(ResolvedPackage {
            ecosystem: "npm".to_string(),
            purl_type: "npm".to_string(),
            name,
            version,
            direct: false,
        });
    }
    Ok(out)
}

// ---- pnpm-lock.yaml (lockfileVersion 5.x "/name/ver", 6.x "/name@ver", 9 "name@ver") ----

/// `(name, version)` from a pnpm `packages:` key across lockfile versions.
/// Peer-dependency qualifiers — `(peer@1.0)` suffixes in v6/v9, `_peer@1.0`
/// in v5 — are stripped from the version.
fn pnpm_key_parts(key: &str) -> Option<(String, String)> {
    let key = key.trim().trim_start_matches('/');
    let key = key.split('(').next().unwrap_or(key);
    // v5 form first — the version is the last path segment (digit-leading),
    // and its `_peer@x` qualifier contains an `@` that would fool the
    // name@version split below.
    if let Some((name, version)) = key.rsplit_once('/') {
        if version.starts_with(|c: char| c.is_ascii_digit()) {
            let version = version.split('_').next().unwrap_or(version);
            return (!name.is_empty() && !version.is_empty())
                .then(|| (name.to_string(), version.to_string()));
        }
    }
    // v6/v9 form: name@version, names possibly scoped (@scope/name).
    let at = key.rfind('@').filter(|&i| i > 0)?;
    let (name, version) = (&key[..at], &key[at + 1..]);
    let version = version.split('_').next().unwrap_or(version);
    (!name.is_empty() && !version.is_empty())
        .then(|| (name.to_string(), version.to_string()))
}

fn parse_pnpm_lock(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(text).map_err(|e| format!("pnpm-lock.yaml: {e}"))?;
    // v9 keeps metadata under `packages` and resolutions under `snapshots`;
    // earlier versions have `packages` only. Either carries name@version keys.
    let map = ["packages", "snapshots"]
        .iter()
        .find_map(|section| doc.get(section).and_then(|v| v.as_mapping()));
    let Some(map) = map else {
        return Ok(vec![]); // an empty workspace lockfile has no packages block
    };
    let mut out = Vec::new();
    for (key, _) in map {
        let Some(key) = key.as_str() else { continue };
        if let Some((name, version)) = pnpm_key_parts(key) {
            out.push(ResolvedPackage {
                ecosystem: "npm".to_string(),
                purl_type: "npm".to_string(),
                name,
                version: Some(version),
                direct: false,
            });
        }
    }
    Ok(out)
}

// ---- go.sum (module version hash; the whole build graph, deduplicated) ----

fn parse_go_sum(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(module), Some(version)) = (fields.next(), fields.next()) else {
            continue;
        };
        // Each module appears as `v1.2.3 h1:…` and `v1.2.3/go.mod h1:…`.
        let version = version.strip_suffix("/go.mod").unwrap_or(version);
        // OSV Go versions carry no `v` prefix.
        let version = version.strip_prefix('v').unwrap_or(version);
        if version.is_empty() || !seen.insert((module.to_string(), version.to_string())) {
            continue;
        }
        out.push(ResolvedPackage {
            ecosystem: "Go".to_string(),
            purl_type: "golang".to_string(),
            name: module.to_string(),
            version: Some(version.to_string()),
            // go.sum covers the whole module graph; directness lives in go.mod.
            direct: false,
        });
    }
    Ok(out)
}

// ---- poetry.lock (TOML [[package]]; local directory/file sources skipped) ----

#[derive(Deserialize)]
struct PoetryLock {
    #[serde(default)]
    package: Vec<PoetryPackage>,
}

#[derive(Deserialize)]
struct PoetryPackage {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    source: Option<PoetrySource>,
}

#[derive(Deserialize)]
struct PoetrySource {
    #[serde(rename = "type", default)]
    source_type: Option<String>,
}

fn parse_poetry_lock(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let lock: PoetryLock = toml::from_str(text).map_err(|e| format!("poetry.lock: {e}"))?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| {
            // `directory`/`file` sources are the user's own local code.
            !matches!(
                p.source.as_ref().and_then(|s| s.source_type.as_deref()),
                Some("directory") | Some("file")
            )
        })
        .map(|p| ResolvedPackage {
            ecosystem: "PyPI".to_string(),
            purl_type: "pypi".to_string(),
            name: p.name,
            version: p.version,
            direct: false,
        })
        .collect())
}

// ---- Gemfile.lock (bundler's indented text format) ----

/// `rails (7.0.4)` → (name, version). Platform-suffixed versions
/// (`nokogiri (1.13.8-x86_64-linux)`) keep only the version part: RubyGems
/// ordering reads `-` as a pre-release marker, which would rank the platform
/// build *below* its own plain version. Dash pre-releases are canonically
/// written with dots in gem versions, so this loses nothing real.
fn gem_spec_parts(s: &str) -> Option<(String, String)> {
    let (name, rest) = s.split_once(" (")?;
    let version = rest.strip_suffix(')')?;
    let version = version.split('-').next().unwrap_or(version);
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

fn parse_gemfile_lock(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let mut section = "";
    let mut in_specs = false;
    let mut packages: Vec<(String, String)> = Vec::new();
    let mut direct: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for line in text.lines() {
        if !line.starts_with([' ', '\t']) && !line.trim().is_empty() {
            section = line.trim();
            in_specs = false;
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        let content = line.trim();
        match section {
            // GEM (registry) and GIT sections list resolvable packages;
            // PATH specs are the user's own local gems.
            "GEM" | "GIT" | "PATH" => {
                if content == "specs:" {
                    in_specs = true;
                } else if in_specs && indent == 4 && section != "PATH" {
                    if let Some(parts) = gem_spec_parts(content) {
                        packages.push(parts);
                    }
                }
                // indent 6 lines are dependency constraints — not resolutions.
            }
            "DEPENDENCIES" => {
                let name = content
                    .split([' ', '(', '!'])
                    .next()
                    .unwrap_or("")
                    .to_string();
                if !name.is_empty() {
                    direct.insert(name);
                }
            }
            _ => {}
        }
    }

    Ok(packages
        .into_iter()
        .map(|(name, version)| ResolvedPackage {
            ecosystem: "RubyGems".to_string(),
            purl_type: "gem".to_string(),
            direct: direct.contains(&name),
            name,
            version: Some(version),
        })
        .collect())
}

// ---- composer.lock (JSON packages + packages-dev) ----

#[derive(Deserialize)]
struct ComposerLock {
    #[serde(default)]
    packages: Vec<ComposerPackage>,
    #[serde(default, rename = "packages-dev")]
    packages_dev: Vec<ComposerPackage>,
}

#[derive(Deserialize)]
struct ComposerPackage {
    name: String,
    #[serde(default)]
    version: Option<String>,
}

fn parse_composer_lock(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let lock: ComposerLock =
        serde_json::from_str(text).map_err(|e| format!("composer.lock: {e}"))?;
    Ok(lock
        .packages
        .into_iter()
        .chain(lock.packages_dev)
        .map(|p| ResolvedPackage {
            ecosystem: "Packagist".to_string(),
            purl_type: "composer".to_string(),
            name: p.name,
            // Composer treats `v1.2.3` and `1.2.3` as the same version.
            version: p
                .version
                .map(|v| v.strip_prefix('v').unwrap_or(&v).to_string()),
            direct: false,
        })
        .collect())
}

// ---- requirements.txt (pinned lines only; SCA-001 for the rest) ----

fn parse_requirements_txt(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue; // options like -r, -e, --hash
        }
        // Only exact pins (`==`) are resolvable; anything else is unpinned.
        if let Some((name, version)) = line.split_once("==") {
            let name = name.trim().split([';', '[']).next().unwrap_or("").trim();
            let version = version.split_whitespace().next().unwrap_or("").trim();
            if name.is_empty() || version.is_empty() {
                continue;
            }
            out.push(ResolvedPackage {
                ecosystem: "PyPI".to_string(),
                purl_type: "pypi".to_string(),
                name: name.to_string(),
                version: Some(version.to_string()),
                direct: true,
            });
        } else {
            // Unpinned declaration (SCA-001): record without a version.
            let name = line
                .split(['>', '<', '~', '!', '=', ';', '[', ' '])
                .next()
                .unwrap_or("")
                .trim();
            if !name.is_empty() {
                out.push(ResolvedPackage {
                    ecosystem: "PyPI".to_string(),
                    purl_type: "pypi".to_string(),
                    name: name.to_string(),
                    version: None,
                    direct: true,
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_lock_parses() {
        let text = r#"
version = 3
[[package]]
name = "lodash-rs"
version = "1.10.0"

[[package]]
name = "serde"
version = "1.0.200"
"#;
        let pkgs = parse_cargo_lock(text).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].purl(), "pkg:cargo/lodash-rs@1.10.0");
    }

    #[test]
    fn package_lock_v3_parses_direct_and_transitive() {
        let text = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": { "name": "root" },
            "node_modules/lodash": { "version": "4.17.20" },
            "node_modules/a/node_modules/lodash": { "version": "4.17.19" }
          }
        }"#;
        let pkgs = parse_package_lock(text).unwrap();
        assert_eq!(pkgs.len(), 2);
        let direct = pkgs.iter().find(|p| p.direct).unwrap();
        assert_eq!(direct.version.as_deref(), Some("4.17.20"));
        assert!(pkgs.iter().any(|p| !p.direct));
    }

    #[test]
    fn uv_lock_parses_registry_packages_and_skips_local() {
        let text = r#"
version = 1
revision = 3
requires-python = ">=3.13"

[manifest]
members = ["my-app", "my-lib"]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]
sdist = { url = "https://example.invalid/requests.tar.gz", hash = "sha256:aa", size = 1 }

[[package]]
name = "urllib3"
version = "1.26.5"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[package.dev-dependencies]
dev = [
    { name = "black" },
]

[[package]]
name = "my-lib"
version = "0.1.0"
source = { editable = "../my-lib" }

[[package]]
name = "black"
version = "24.4.2"
source = { registry = "https://pypi.org/simple" }
"#;
        let pkgs = parse_uv_lock(text).unwrap();
        // Local packages (virtual root, editable member) are not inventoried.
        assert_eq!(pkgs.len(), 3);
        assert!(!pkgs.iter().any(|p| p.name == "my-app" || p.name == "my-lib"));

        let requests = pkgs.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(requests.purl(), "pkg:pypi/requests@2.31.0");
        assert_eq!(requests.ecosystem, "PyPI");
        assert!(requests.direct, "declared by the virtual root");

        // Dev-group deps of a local package are direct too.
        assert!(pkgs.iter().find(|p| p.name == "black").unwrap().direct);
        // Transitive: only reachable via requests.
        assert!(!pkgs.iter().find(|p| p.name == "urllib3").unwrap().direct);
    }

    #[test]
    fn uv_lock_malformed_degrades_with_reason() {
        let err = parse_uv_lock("version = [not toml").unwrap_err();
        assert!(err.starts_with("uv.lock:"));
    }

    #[test]
    fn yarn_v1_parses_plain_and_scoped() {
        let text = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

lodash@^4.17.20, lodash@~4.17.19:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c5"
  integrity sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==

"@babel/core@^7.12.0":
  version "7.20.12"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.20.12.tgz"
"#;
        let pkgs = parse_yarn_lock(text).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].purl(), "pkg:npm/lodash@4.17.21");
        assert_eq!(pkgs[1].purl(), "pkg:npm/@babel/core@7.20.12");
    }

    #[test]
    fn yarn_berry_parses_and_skips_workspace() {
        let text = r#"__metadata:
  version: 8
  cacheKey: 10

"lodash@npm:^4.17.20":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"my-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-app@workspace:."
"#;
        let pkgs = parse_yarn_lock(text).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].purl(), "pkg:npm/lodash@4.17.21");
    }

    #[test]
    fn pnpm_key_formats_across_versions() {
        // v5, v6, v9 key shapes, scoped and peer-qualified.
        assert_eq!(
            pnpm_key_parts("/lodash/4.17.21"),
            Some(("lodash".into(), "4.17.21".into()))
        );
        assert_eq!(
            pnpm_key_parts("/@babel/core/7.20.12"),
            Some(("@babel/core".into(), "7.20.12".into()))
        );
        assert_eq!(
            pnpm_key_parts("/lodash@4.17.21"),
            Some(("lodash".into(), "4.17.21".into()))
        );
        assert_eq!(
            pnpm_key_parts("@babel/core@7.20.12(supports-color@9.0.0)"),
            Some(("@babel/core".into(), "7.20.12".into()))
        );
        assert_eq!(
            pnpm_key_parts("/foo/1.0.0_bar@2.0.0"),
            Some(("foo".into(), "1.0.0".into()))
        );
    }

    #[test]
    fn pnpm_lock_parses_packages_map() {
        let text = r#"lockfileVersion: '9.0'

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-v2kD}

  '@babel/core@7.20.12':
    resolution: {integrity: sha512-XsMf}
"#;
        let pkgs = parse_pnpm_lock(text).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.iter().any(|p| p.purl() == "pkg:npm/lodash@4.17.21"));
    }

    #[test]
    fn go_sum_dedupes_and_strips_v() {
        let text = "\
github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
golang.org/x/text v0.3.8 h1:nAL+RVCQ9uMn3vJZbV+MRnydTJFPf8qqY42YiA6MrqY=
golang.org/x/text v0.3.8/go.mod h1:E6s5w1FMmriuDzIBO73fBruAKo1PCIq6d2Q6DHfQ8WQ=
";
        let pkgs = parse_go_sum(text).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].purl(), "pkg:golang/github.com/pkg/errors@0.9.1");
        assert_eq!(pkgs[0].ecosystem, "Go");
    }

    #[test]
    fn poetry_lock_skips_local_sources() {
        let text = r#"
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."

[[package]]
name = "my-local"
version = "0.1.0"

[package.source]
type = "directory"
url = "../my-local"
"#;
        let pkgs = parse_poetry_lock(text).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].purl(), "pkg:pypi/requests@2.31.0");
    }

    #[test]
    fn gemfile_lock_sections_direct_and_platform() {
        let text = "\
GIT
  remote: https://github.com/org/custom-gem.git
  revision: abc123
  specs:
    custom-gem (0.5.0)

PATH
  remote: .
  specs:
    my-engine (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.13.8-x86_64-linux)
      racc (~> 1.4)
    racc (1.6.0)
    rails (7.0.4)
      actionpack (= 7.0.4)

DEPENDENCIES
  custom-gem!
  nokogiri (>= 1.13)
  rails
";
        let pkgs = parse_gemfile_lock(text).unwrap();
        // PATH spec (local engine) is skipped; GIT and GEM specs are kept.
        assert_eq!(pkgs.len(), 4);
        assert!(!pkgs.iter().any(|p| p.name == "my-engine"));
        let nokogiri = pkgs.iter().find(|p| p.name == "nokogiri").unwrap();
        // Platform suffix stripped so RubyGems ordering compares releases.
        assert_eq!(nokogiri.version.as_deref(), Some("1.13.8"));
        assert!(nokogiri.direct);
        assert!(pkgs.iter().find(|p| p.name == "rails").unwrap().direct);
        // Transitive constraint lines (indent 6) are not packages.
        assert!(!pkgs.iter().find(|p| p.name == "racc").unwrap().direct);
        assert_eq!(pkgs.iter().filter(|p| p.name == "racc").count(), 1);
    }

    #[test]
    fn composer_lock_strips_v_and_includes_dev() {
        let text = r#"{
          "packages": [
            { "name": "monolog/monolog", "version": "v2.8.0" }
          ],
          "packages-dev": [
            { "name": "phpunit/phpunit", "version": "9.5.27" }
          ]
        }"#;
        let pkgs = parse_composer_lock(text).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].purl(), "pkg:composer/monolog/monolog@2.8.0");
        assert_eq!(pkgs[0].ecosystem, "Packagist");
    }

    #[test]
    fn requirements_pinned_vs_unpinned() {
        let text = "Django==3.2.14\nrequests>=2.0  # unpinned\nflask\n-r other.txt\n";
        let pkgs = parse_requirements_txt(text).unwrap();
        let django = pkgs.iter().find(|p| p.name == "Django").unwrap();
        assert_eq!(django.version.as_deref(), Some("3.2.14"));
        // Unpinned entries are kept with no version (SCA-001), not dropped.
        assert!(pkgs
            .iter()
            .any(|p| p.name == "requests" && p.version.is_none()));
        assert!(pkgs
            .iter()
            .any(|p| p.name == "flask" && p.version.is_none()));
    }
}
