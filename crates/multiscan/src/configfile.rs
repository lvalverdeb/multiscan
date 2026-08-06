//! Config discovery and precedence (spec 4.5): TOML discovered upward from
//! the scan root; CLI flags override file values; file values override
//! defaults. A malformed config — including a `[[suppress]]` entry missing
//! justification/approver/expires (CLI-006) — is a usage error, exit 2.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use multiscan_core::Config;

/// An empty configuration (all defaults).
pub fn empty_config() -> Config {
    Config {
        scan: None,
        gate: None,
        risk: None,
        feeds: None,
        rules: None,
        suppress: vec![],
    }
}

/// Find `multiscan.toml` walking upward from `root`.
pub fn discover(root: &Path) -> Option<PathBuf> {
    let start = root.canonicalize().ok()?;
    let mut dir = Some(start.as_path());
    while let Some(d) = dir {
        let candidate = d.join("multiscan.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}

/// Load the effective config: `--config` beats discovery; no file means all
/// defaults. Parse failures are errors (the caller maps them to exit 2).
/// The generated `Config` type denies unknown fields and requires the three
/// CLI-006 suppression fields, so schema violations fail here.
pub fn load(explicit: Option<&Path>, root: &Path) -> Result<(Config, Option<PathBuf>)> {
    let path = match explicit {
        Some(p) => Some(p.to_path_buf()),
        None => discover(root),
    };
    match path {
        None => Ok((empty_config(), None)),
        Some(p) => {
            let text = std::fs::read_to_string(&p)
                .with_context(|| format!("reading config {}", p.display()))?;
            let config: Config =
                toml::from_str(&text).with_context(|| format!("invalid config {}", p.display()))?;
            Ok((config, Some(p)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_suppress_fields_are_a_config_error() {
        // CLI-006: no justification/approver/expires → parse error.
        let bad = r#"
[[suppress]]
finding_id = "a3f9c1e0"
justification = "vendored fixture"
"#;
        assert!(toml::from_str::<Config>(bad).is_err());
    }

    #[test]
    fn full_spec_example_parses() {
        let good = r#"
[scan]
layers = ["sca", "secrets", "iac"]
profile = "standard"
exclude = ["vendor/**", "**/testdata/**", "*.min.js"]

[gate]
fail_on = 80.0
baseline = ".multiscan/baseline.json"
ignore_unfixable = false

[risk]
asset_criticality = "high"
data_classification = "sensitive"

[feeds]
max_age = "7d"
offline = false

[rules]
sca_db = "osv@2026-08-05"
iac_pack = "cis-bundle@1.9.0"
secrets_pack = "builtin@2.0.0"

[[suppress]]
finding_id = "a3f9c1e0"
justification = "Vendored test fixture, not shipped"
approver = "sec-team"
expires = "2026-11-01"
"#;
        let config: Config = toml::from_str(good).expect("spec 4.5 example must parse");
        assert_eq!(config.suppress.len(), 1);
        assert!(config.gate.is_some());
    }

    #[test]
    fn severity_fail_on_parses() {
        let config: Config = toml::from_str("[gate]\nfail_on = \"high\"\n").unwrap();
        assert!(config.gate.unwrap().fail_on.is_some());
    }

    #[test]
    fn unknown_keys_rejected() {
        assert!(toml::from_str::<Config>("[scan]\nbogus = 1\n").is_err());
    }

    /// ADR 0004: per-layer [scan.<layer>] sections parse, and only the three
    /// file-based layers exist — anything else is a config error.
    #[test]
    fn per_layer_exclude_sections_parse() {
        let good = r#"
[scan]
exclude = [".idea/**"]

[scan.secrets]
exclude = ["**/*.lock"]

[scan.sca]
exclude = ["fixtures/**"]

[scan.iac]
exclude = ["examples/**"]
"#;
        let config: Config = toml::from_str(good).expect("per-layer sections must parse");
        let scan = config.scan.unwrap();
        assert_eq!(scan.secrets.unwrap().exclude, vec!["**/*.lock"]);
        assert_eq!(scan.sca.unwrap().exclude, vec!["fixtures/**"]);
        assert_eq!(scan.iac.unwrap().exclude, vec!["examples/**"]);

        // No [scan.probe] (no local files) and no [scan.sast] (v1 scaffold).
        assert!(toml::from_str::<Config>("[scan.probe]\nexclude = [\"x\"]\n").is_err());
        assert!(toml::from_str::<Config>("[scan.sast]\nexclude = [\"x\"]\n").is_err());
    }
}
