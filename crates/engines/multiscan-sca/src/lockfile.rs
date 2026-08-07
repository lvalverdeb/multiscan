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
        "gradle.lockfile" => Some(parse_gradle_lockfile),
        // pom.xml is Maven's primary source (Maven has no separate lockfile),
        // so it is a regular input, not a shadowed manifest.
        "pom.xml" => Some(parse_pom_xml),
        // Manifests: parsed only as fallback when their lockfile is absent
        // (see `shadowing_lockfiles`); ranges surface as SCA-001 unpinned.
        "package.json" => Some(parse_package_json),
        "pyproject.toml" => Some(parse_pyproject),
        "go.mod" => Some(parse_go_mod),
        "Gemfile" => Some(parse_gemfile),
        "composer.json" => Some(parse_composer_json),
        "Cargo.toml" => Some(parse_cargo_manifest),
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
    "gradle.lockfile",
    "pom.xml",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Gemfile",
    "composer.json",
    "Cargo.toml",
];

/// Lockfiles that make a manifest redundant. A manifest is a *fallback*: if
/// any of these exists in the manifest's directory or an ancestor (workspace
/// roots hold the lock for member manifests — Cargo, Go), the lockfile's
/// exact resolutions win and the manifest is not parsed, so a repo is never
/// double-reported.
pub fn shadowing_lockfiles(manifest: &str) -> &'static [&'static str] {
    match manifest {
        "package.json" => &[
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
        ],
        "pyproject.toml" => &["uv.lock", "poetry.lock"],
        "go.mod" => &["go.sum"],
        "Gemfile" => &["Gemfile.lock"],
        "composer.json" => &["composer.lock"],
        "Cargo.toml" => &["Cargo.lock"],
        _ => &[],
    }
}

/// Whether this file name is a manifest (fallback-only input).
pub fn is_manifest(file_name: &str) -> bool {
    !shadowing_lockfiles(file_name).is_empty()
}

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
    for package in lock
        .package
        .iter()
        .filter(|p| uv_source_is_local(&p.source))
    {
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
    (!name.is_empty() && !version.is_empty()).then(|| (name.to_string(), version.to_string()))
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

// ---- gradle.lockfile (Gradle dependency locking; group:artifact:version) ----

fn parse_gradle_lockfile(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        // Comments and the `empty=<configs>` marker line carry no coordinate.
        if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
            continue;
        }
        // `group:artifact:version=conf1,conf2`
        let coord = line.split('=').next().unwrap_or("");
        let parts: Vec<&str> = coord.split(':').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            continue;
        }
        out.push(ResolvedPackage {
            ecosystem: "Maven".to_string(),
            purl_type: "maven".to_string(),
            name: format!("{}:{}", parts[0], parts[1]),
            version: Some(parts[2].to_string()),
            // gradle.lockfile records the resolved graph, not direct/transitive.
            direct: false,
        });
    }
    Ok(out)
}

// ---- pom.xml (Maven; bounded hand-rolled tag scan, comment-stripped) ----

const MAX_POM_DEPENDENCIES: usize = 100_000;

/// Inner text of the first `<tag>…</tag>` within `block`, tolerating an
/// attribute list on the open tag (`<version foo="bar">`). `None` if absent.
fn xml_first(block: &str, tag: &str) -> Option<String> {
    let mut from = 0;
    let open = format!("<{tag}");
    while let Some(rel) = block[from..].find(&open) {
        let after = from + rel + open.len();
        // The char after the tag name must end the name (`>`, space, `/`).
        match block[after..].chars().next() {
            Some('>') => {
                let start = after + 1;
                let end = block[start..].find(&format!("</{tag}>"))?;
                return Some(block[start..start + end].trim().to_string());
            }
            Some(c) if c.is_whitespace() => {
                let gt = block[after..].find('>')? + after + 1;
                let end = block[gt..].find(&format!("</{tag}>"))?;
                return Some(block[gt..gt + end].trim().to_string());
            }
            // A longer tag name (e.g. `<versioning>` when tag=`version`); keep
            // looking past this occurrence.
            _ => from = after,
        }
    }
    None
}

/// Strip XML comments so commented-out `<dependency>` blocks never register.
/// Bounded: unterminated comments drop the remainder.
fn strip_xml_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        match rest[start..].find("-->") {
            Some(end) => rest = &rest[start + end + 3..],
            None => return out, // unterminated: drop the tail
        }
    }
    out.push_str(rest);
    out
}

fn parse_pom_xml(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let text = strip_xml_comments(text);
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = text[from..].find("<dependency>") {
        if out.len() >= MAX_POM_DEPENDENCIES {
            break;
        }
        let start = from + rel + "<dependency>".len();
        let Some(close) = text[start..].find("</dependency>") else {
            break;
        };
        let block = &text[start..start + close];
        from = start + close + "</dependency>".len();

        let (Some(group), Some(artifact)) =
            (xml_first(block, "groupId"), xml_first(block, "artifactId"))
        else {
            continue;
        };
        if group.is_empty() || artifact.is_empty() {
            continue;
        }
        // An exact literal pins; a property reference (`${jackson.version}`),
        // a range (`[1.0,2.0)`), or an absent version (managed elsewhere) is
        // unpinned — surfaced as SCA-001, never silently dropped.
        let version = xml_first(block, "version").filter(|v| {
            !v.is_empty() && !v.contains('$') && !v.starts_with('[') && !v.starts_with('(')
        });
        out.push(ResolvedPackage {
            ecosystem: "Maven".to_string(),
            purl_type: "maven".to_string(),
            name: format!("{group}:{artifact}"),
            version,
            direct: true,
        });
    }
    Ok(out)
}

// ---- Manifests (fallback when no lockfile shadows them) ----
//
// Manifests declare ranges, not resolutions. An exact declaration becomes a
// resolvable package; anything else is recorded without a version so the
// engine emits the SCA-001 unpinned finding instead of silently skipping.

fn manifest_package(
    ecosystem: &str,
    purl_type: &str,
    name: &str,
    version: Option<String>,
    direct: bool,
) -> ResolvedPackage {
    ResolvedPackage {
        ecosystem: ecosystem.to_string(),
        purl_type: purl_type.to_string(),
        name: name.to_string(),
        version,
        direct,
    }
}

// ---- package.json ----

#[derive(Deserialize)]
struct NpmManifest {
    #[serde(default)]
    dependencies: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: std::collections::BTreeMap<String, String>,
}

fn parse_package_json(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let manifest: NpmManifest =
        serde_json::from_str(text).map_err(|e| format!("package.json: {e}"))?;
    let mut out = Vec::new();
    for (name, spec) in manifest
        .dependencies
        .iter()
        .chain(&manifest.dev_dependencies)
        .chain(&manifest.optional_dependencies)
    {
        // Non-registry specifiers are the user's own or unresolvable here.
        if spec.starts_with("file:")
            || spec.starts_with("link:")
            || spec.starts_with("workspace:")
            || spec.starts_with("git")
            || spec.starts_with("http")
            || spec.starts_with("github:")
        {
            continue;
        }
        // npm: a bare version is an exact pin; anything else is a range.
        let version = semver::Version::parse(spec).ok().map(|v| v.to_string());
        out.push(manifest_package("npm", "npm", name, version, true));
    }
    Ok(out)
}

// ---- pyproject.toml (PEP 621 [project] and [tool.poetry]) ----

/// One PEP 508 requirement string → package. `flask[async]==2.3.2; marker`
/// pins; `requests>=2,<3` records unpinned.
fn pep508_package(spec: &str) -> Option<ResolvedPackage> {
    let spec = spec.split(';').next().unwrap_or("").trim();
    if spec.is_empty() {
        return None;
    }
    let name = spec
        .split(['[', '<', '>', '=', '!', '~', ' ', '('])
        .next()
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        return None;
    }
    let version = spec.split_once("==").and_then(|(_, v)| {
        let v = v.trim().trim_end_matches(')');
        let v = v.split([',', ' ']).next().unwrap_or("");
        // `==1.2.*` is still a range.
        (!v.is_empty() && !v.contains('*')).then(|| v.to_string())
    });
    Some(manifest_package("PyPI", "pypi", name, version, true))
}

/// A poetry constraint (`"1.2.3"` exact, `"^1.2"`/`"*"` range) → version.
fn poetry_exact(constraint: &str) -> Option<String> {
    let v = constraint.trim();
    (!v.is_empty()
        && v.chars().next().is_some_and(|c| c.is_ascii_digit())
        && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '.'))
    .then(|| v.to_string())
}

fn parse_pyproject(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let doc: toml::Value = toml::from_str(text).map_err(|e| format!("pyproject.toml: {e}"))?;
    let mut out = Vec::new();

    // PEP 621: [project] dependencies + [project.optional-dependencies].
    if let Some(project) = doc.get("project") {
        let groups = project.get("dependencies").into_iter().chain(
            project
                .get("optional-dependencies")
                .and_then(|t| t.as_table())
                .into_iter()
                .flat_map(|t| t.values()),
        );
        for group in groups {
            for spec in group.as_array().into_iter().flatten() {
                if let Some(pkg) = spec.as_str().and_then(pep508_package) {
                    out.push(pkg);
                }
            }
        }
    }

    // Poetry: [tool.poetry.dependencies] and [tool.poetry.group.*.dependencies].
    if let Some(poetry) = doc.get("tool").and_then(|t| t.get("poetry")) {
        let group_tables = poetry
            .get("group")
            .and_then(|g| g.as_table())
            .into_iter()
            .flat_map(|groups| groups.values())
            .filter_map(|g| g.get("dependencies"));
        for table in poetry.get("dependencies").into_iter().chain(group_tables) {
            let Some(table) = table.as_table() else {
                continue;
            };
            for (name, constraint) in table {
                if name == "python" {
                    continue;
                }
                let version = match constraint {
                    toml::Value::String(s) => poetry_exact(s),
                    toml::Value::Table(t) => {
                        // Local/git sources are not registry packages.
                        if t.contains_key("path") || t.contains_key("git") {
                            continue;
                        }
                        t.get("version")
                            .and_then(|v| v.as_str())
                            .and_then(poetry_exact)
                    }
                    _ => None,
                };
                out.push(manifest_package("PyPI", "pypi", name, version, true));
            }
        }
    }
    Ok(out)
}

// ---- go.mod (require directives; `// indirect` marks transitives) ----

fn go_mod_entry(code: &str, comment: &str) -> Option<ResolvedPackage> {
    let mut fields = code.split_whitespace();
    let (module, version) = (fields.next()?, fields.next()?);
    let version = version.strip_prefix('v')?;
    Some(manifest_package(
        "Go",
        "golang",
        module,
        Some(version.to_string()),
        !comment.contains("indirect"),
    ))
}

fn parse_go_mod(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let mut out = Vec::new();
    let mut block: Option<&str> = None;
    for line in text.lines() {
        let (code, comment) = line.split_once("//").unwrap_or((line, ""));
        let code = code.trim();
        if let Some(kind) = block {
            if code == ")" {
                block = None;
            } else if kind == "require" && !code.is_empty() {
                out.extend(go_mod_entry(code, comment));
            }
            continue;
        }
        for kind in ["require", "exclude", "replace", "retract"] {
            if let Some(rest) = code.strip_prefix(kind) {
                let rest = rest.trim();
                if rest == "(" {
                    block = Some(kind);
                } else if kind == "require" {
                    out.extend(go_mod_entry(rest, comment));
                }
                break;
            }
        }
    }
    Ok(out)
}

// ---- Gemfile (gem "name", "constraint" lines; no regex, hand-tokenized) ----

/// Quoted strings in a Gemfile argument list, in order.
fn quoted_args(rest: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut chars = rest.char_indices();
    while let Some((start, c)) = chars.next() {
        if c == '"' || c == '\'' {
            if let Some(len) = rest[start + 1..].find(c) {
                out.push(&rest[start + 1..start + 1 + len]);
                // Skip past the closing quote.
                for _ in 0..len + 1 {
                    chars.next();
                }
            }
        }
    }
    out
}

fn parse_gemfile(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line
            .strip_prefix("gem ")
            .or_else(|| line.strip_prefix("gem("))
        else {
            continue;
        };
        // path:/git:/github: gems are not registry-resolvable.
        if ["path:", "git:", "github:", ":path", ":git", ":github"]
            .iter()
            .any(|k| rest.contains(k))
        {
            continue;
        }
        let args = quoted_args(rest);
        let Some(name) = args.first().filter(|n| !n.is_empty()) else {
            continue;
        };
        // Exact only when a constraint is a bare version (no operator).
        let version = args
            .get(1)
            .filter(|v| {
                v.chars().next().is_some_and(|c| c.is_ascii_digit())
                    && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '.')
            })
            .map(|v| v.to_string());
        out.push(manifest_package("RubyGems", "gem", name, version, true));
    }
    Ok(out)
}

// ---- composer.json (require + require-dev; platform packages skipped) ----

#[derive(Deserialize)]
struct ComposerManifest {
    #[serde(default)]
    require: std::collections::BTreeMap<String, String>,
    #[serde(default, rename = "require-dev")]
    require_dev: std::collections::BTreeMap<String, String>,
}

fn parse_composer_json(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let manifest: ComposerManifest =
        serde_json::from_str(text).map_err(|e| format!("composer.json: {e}"))?;
    let mut out = Vec::new();
    for (name, constraint) in manifest.require.iter().chain(&manifest.require_dev) {
        // `php` and ext-*/lib-* are platform requirements, not packages.
        if name == "php" || name.starts_with("ext-") || name.starts_with("lib-") {
            continue;
        }
        let v = constraint.trim().trim_start_matches('v');
        let version = (v.chars().next().is_some_and(|c| c.is_ascii_digit())
            && v.chars().all(|c| c.is_ascii_digit() || c == '.'))
        .then(|| v.to_string());
        out.push(manifest_package(
            "Packagist",
            "composer",
            name,
            version,
            true,
        ));
    }
    Ok(out)
}

// ---- Cargo.toml ([dependencies] & friends; caret semantics ⇒ `=` pins) ----

fn parse_cargo_manifest(text: &str) -> Result<Vec<ResolvedPackage>, String> {
    let doc: toml::Value = toml::from_str(text).map_err(|e| format!("Cargo.toml: {e}"))?;
    let mut out = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = doc.get(section).and_then(|v| v.as_table()) else {
            continue;
        };
        for (key, spec) in table {
            let (name, requirement) = match spec {
                toml::Value::String(req) => (key.as_str(), Some(req.as_str())),
                toml::Value::Table(t) => {
                    // Local/git/workspace-inherited deps are not registry input.
                    if t.contains_key("path")
                        || t.contains_key("git")
                        || t.contains_key("workspace")
                    {
                        continue;
                    }
                    (
                        // `foo = { package = "bar" }` renames; `bar` is real.
                        t.get("package").and_then(|p| p.as_str()).unwrap_or(key),
                        t.get("version").and_then(|v| v.as_str()),
                    )
                }
                _ => continue,
            };
            // Cargo's bare `1.2.3` means `^1.2.3` — only `=1.2.3` is exact.
            let version = requirement
                .and_then(|r| r.trim().strip_prefix('='))
                .map(|v| v.trim().to_string());
            out.push(manifest_package("crates.io", "cargo", name, version, true));
        }
    }
    Ok(out)
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
        assert!(!pkgs
            .iter()
            .any(|p| p.name == "my-app" || p.name == "my-lib"));

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
    fn package_json_exact_vs_range() {
        let text = r#"{
          "dependencies": { "lodash": "4.17.20", "react": "^18.2.0", "local": "file:../local" },
          "devDependencies": { "jest": "~29.0.0" }
        }"#;
        let pkgs = parse_package_json(text).unwrap();
        assert_eq!(pkgs.len(), 3, "file: dep skipped");
        let lodash = pkgs.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.version.as_deref(), Some("4.17.20"));
        assert!(lodash.direct);
        // Ranges are recorded unpinned (SCA-001), never dropped.
        assert!(pkgs
            .iter()
            .find(|p| p.name == "react")
            .unwrap()
            .version
            .is_none());
        assert!(pkgs
            .iter()
            .find(|p| p.name == "jest")
            .unwrap()
            .version
            .is_none());
    }

    #[test]
    fn pyproject_pep621_and_poetry() {
        let text = r#"
[project]
dependencies = ["flask==2.3.2", "requests>=2,<3", "uvicorn[standard]==0.23.1; python_version > '3.8'"]

[tool.poetry.dependencies]
python = "^3.11"
django = "4.2.3"
celery = { version = "^5.3", extras = ["redis"] }
mylib = { path = "../mylib" }
"#;
        let pkgs = parse_pyproject(text).unwrap();
        assert!(pkgs.iter().all(|p| p.name != "python" && p.name != "mylib"));
        assert_eq!(
            pkgs.iter()
                .find(|p| p.name == "flask")
                .unwrap()
                .version
                .as_deref(),
            Some("2.3.2")
        );
        assert_eq!(
            pkgs.iter()
                .find(|p| p.name == "uvicorn")
                .unwrap()
                .version
                .as_deref(),
            Some("0.23.1")
        );
        assert!(pkgs
            .iter()
            .find(|p| p.name == "requests")
            .unwrap()
            .version
            .is_none());
        assert_eq!(
            pkgs.iter()
                .find(|p| p.name == "django")
                .unwrap()
                .version
                .as_deref(),
            Some("4.2.3")
        );
        assert!(pkgs
            .iter()
            .find(|p| p.name == "celery")
            .unwrap()
            .version
            .is_none());
    }

    #[test]
    fn go_mod_blocks_directness_and_other_directives() {
        let text = "\
module example.com/app

go 1.22

require (
\tgithub.com/gin-gonic/gin v1.9.0
\tgolang.org/x/text v0.13.0 // indirect
)

require github.com/single/dep v1.0.0

replace (
\texample.com/old => example.com/new v9.9.9
)
";
        let pkgs = parse_go_mod(text).unwrap();
        assert_eq!(pkgs.len(), 3, "replace block must not contribute");
        let gin = pkgs
            .iter()
            .find(|p| p.name == "github.com/gin-gonic/gin")
            .unwrap();
        assert_eq!(gin.version.as_deref(), Some("1.9.0"));
        assert!(gin.direct);
        assert!(
            !pkgs
                .iter()
                .find(|p| p.name == "golang.org/x/text")
                .unwrap()
                .direct
        );
        assert!(
            pkgs.iter()
                .find(|p| p.name == "github.com/single/dep")
                .unwrap()
                .direct
        );
    }

    #[test]
    fn gemfile_constraints_and_sources() {
        let text = "\
source 'https://rubygems.org'

gem 'rails', '7.0.4'
gem \"nokogiri\", \">= 1.13\"
gem 'internal', path: '../internal'
gem 'unconstrained'
";
        let pkgs = parse_gemfile(text).unwrap();
        assert_eq!(pkgs.len(), 3, "path: gem skipped");
        assert_eq!(
            pkgs.iter()
                .find(|p| p.name == "rails")
                .unwrap()
                .version
                .as_deref(),
            Some("7.0.4")
        );
        assert!(pkgs
            .iter()
            .find(|p| p.name == "nokogiri")
            .unwrap()
            .version
            .is_none());
        assert!(pkgs
            .iter()
            .find(|p| p.name == "unconstrained")
            .unwrap()
            .version
            .is_none());
    }

    #[test]
    fn composer_json_platform_and_pins() {
        let text = r#"{
          "require": { "php": ">=8.1", "ext-mbstring": "*", "monolog/monolog": "2.8.0" },
          "require-dev": { "phpunit/phpunit": "^9.5" }
        }"#;
        let pkgs = parse_composer_json(text).unwrap();
        assert_eq!(pkgs.len(), 2, "platform requirements skipped");
        assert_eq!(
            pkgs.iter()
                .find(|p| p.name == "monolog/monolog")
                .unwrap()
                .version
                .as_deref(),
            Some("2.8.0")
        );
        assert!(pkgs
            .iter()
            .find(|p| p.name == "phpunit/phpunit")
            .unwrap()
            .version
            .is_none());
    }

    #[test]
    fn cargo_manifest_caret_semantics() {
        let text = r#"
[dependencies]
serde = "1.0.200"
exact = "=2.1.0"
renamed = { package = "real-name", version = "=3.0.0" }
local = { path = "../local" }
inherited = { workspace = true }

[dev-dependencies]
proptest = "1"
"#;
        let pkgs = parse_cargo_manifest(text).unwrap();
        assert_eq!(pkgs.len(), 4, "path/workspace deps skipped");
        // Bare versions are caret ranges in cargo — unpinned.
        assert!(pkgs
            .iter()
            .find(|p| p.name == "serde")
            .unwrap()
            .version
            .is_none());
        assert_eq!(
            pkgs.iter()
                .find(|p| p.name == "exact")
                .unwrap()
                .version
                .as_deref(),
            Some("2.1.0")
        );
        assert_eq!(
            pkgs.iter()
                .find(|p| p.name == "real-name")
                .unwrap()
                .version
                .as_deref(),
            Some("3.0.0")
        );
    }

    #[test]
    fn gradle_lockfile_parses_coordinates() {
        let text = "\
# This is a Gradle generated file for dependency locking.
com.fasterxml.jackson.core:jackson-databind:2.12.1=compileClasspath,runtimeClasspath
org.slf4j:slf4j-api:1.7.30=compileClasspath
empty=annotationProcessor
";
        let pkgs = parse_gradle_lockfile(text).unwrap();
        assert_eq!(pkgs.len(), 2, "empty= line and comment skipped");
        assert_eq!(
            pkgs[0].purl(),
            "pkg:maven/com.fasterxml.jackson.core:jackson-databind@2.12.1"
        );
        assert_eq!(pkgs[0].ecosystem, "Maven");
    }

    #[test]
    fn pom_xml_pins_ranges_and_ignores_comments() {
        let text = r#"
<project xmlns="http://maven.apache.org/POM/4.0.0">
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
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
    </dependency>
    <!--
    <dependency>
      <groupId>evil</groupId><artifactId>commented</artifactId><version>1.0</version>
    </dependency>
    -->
  </dependencies>
</project>
"#;
        let pkgs = parse_pom_xml(text).unwrap();
        assert_eq!(pkgs.len(), 3, "commented dependency must not register");
        assert!(!pkgs.iter().any(|p| p.name.contains("evil")));
        let jackson = pkgs
            .iter()
            .find(|p| p.name == "com.fasterxml.jackson.core:jackson-databind")
            .unwrap();
        assert_eq!(jackson.version.as_deref(), Some("2.12.1"));
        // Property reference and absent version are unpinned (SCA-001).
        assert!(pkgs
            .iter()
            .find(|p| p.name == "org.slf4j:slf4j-api")
            .unwrap()
            .version
            .is_none());
        assert!(pkgs
            .iter()
            .find(|p| p.name == "org.apache.commons:commons-lang3")
            .unwrap()
            .version
            .is_none());
    }

    #[test]
    fn pom_xml_tolerates_attributes_and_namespaced_siblings() {
        // `<version>` must not be confused with `<versioning>`, and an
        // attribute on the open tag is tolerated.
        let text = r#"
<dependency>
  <groupId >org.example</groupId>
  <artifactId>widget</artifactId>
  <version xml:lang="en">3.4.5</version>
</dependency>
"#;
        let pkgs = parse_pom_xml(text).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].version.as_deref(), Some("3.4.5"));
    }

    #[test]
    fn shadowing_map_is_complete() {
        for manifest in [
            "package.json",
            "pyproject.toml",
            "go.mod",
            "Gemfile",
            "composer.json",
            "Cargo.toml",
        ] {
            assert!(is_manifest(manifest));
            assert!(!shadowing_lockfiles(manifest).is_empty());
            // Every shadow is itself a supported lockfile.
            for lock in shadowing_lockfiles(manifest) {
                assert!(SUPPORTED_FILES.contains(lock), "{lock} unsupported");
                assert!(!is_manifest(lock), "{lock} must not be a manifest");
            }
        }
        assert!(!is_manifest("requirements.txt"));
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
