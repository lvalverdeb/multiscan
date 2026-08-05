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
        "package-lock.json" => Some(parse_package_lock),
        "requirements.txt" => Some(parse_requirements_txt),
        _ => None,
    }
}

/// File names this engine recognizes, for cheap applicability checks.
pub const SUPPORTED_FILES: &[&str] = &["Cargo.lock", "package-lock.json", "requirements.txt"];

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
