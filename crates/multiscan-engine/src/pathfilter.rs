//! Compiled exclude globs for file discovery (spec 4.5 `[scan] exclude`,
//! CLI-007; per-layer `[scan.<layer>] exclude`, ADR 0004).
//!
//! The filter is compiled once at config resolution — an invalid glob is a
//! config error there (exit 2), never an engine-time failure — and travels to
//! engines inside `ScanContext`. Engines consult it during their walks:
//! matched files are skipped, and a matched directory path prunes the walk
//! beneath it. Matching is against root-relative POSIX paths (DET-005), so
//! results are identical across platforms.

use std::collections::BTreeMap;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use multiscan_core::{Config, Layer};

/// A glob pattern that failed to compile, with the config section it came
/// from so the exit-2 diagnostic points at the offending line.
#[derive(Debug, thiserror::Error)]
#[error("invalid exclude glob `{pattern}` in [{section}]: {reason}")]
pub struct PathFilterError {
    /// The offending pattern, verbatim.
    pub pattern: String,
    /// Config section it was found in (`scan` or `scan.<layer>`).
    pub section: String,
    /// Why globset rejected it.
    pub reason: String,
}

/// Compiled exclude sets: one global (all layers) plus per-layer extensions.
/// `BTreeMap`, not `HashMap` — the filter sits on the scan path (DET-001).
#[derive(Debug, Clone)]
pub struct PathFilter {
    global: GlobSet,
    per_layer: BTreeMap<Layer, GlobSet>,
}

fn compile(patterns: &[String], section: &str) -> Result<GlobSet, PathFilterError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(pattern)
            // `foo` and `FOO` are different paths; excludes are exact.
            .case_insensitive(false)
            .build()
            .map_err(|e| PathFilterError {
                pattern: pattern.clone(),
                section: section.to_string(),
                reason: e.kind().to_string(),
            })?;
        builder.add(glob);
    }
    builder.build().map_err(|e| PathFilterError {
        pattern: patterns.join(", "),
        section: section.to_string(),
        reason: e.to_string(),
    })
}

impl PathFilter {
    /// A filter that excludes nothing — the default when no config exists,
    /// and the testkit default.
    pub fn empty() -> Self {
        Self {
            global: GlobSet::empty(),
            per_layer: BTreeMap::new(),
        }
    }

    /// Compile the exclude globs of a resolved `Config`. This is the only
    /// constructor from config — callers must not re-derive filters ad hoc,
    /// or `ctx.excludes` and `ctx.config` drift apart.
    pub fn from_config(config: &Config) -> Result<Self, PathFilterError> {
        let Some(scan) = config.scan.as_ref() else {
            return Ok(Self::empty());
        };
        let global = compile(&scan.exclude, "scan")?;
        let mut per_layer = BTreeMap::new();
        let sections: [(Layer, Option<&multiscan_core::LayerScanConfig>, &str); 3] = [
            (Layer::Sca, scan.sca.as_ref(), "scan.sca"),
            (Layer::Secrets, scan.secrets.as_ref(), "scan.secrets"),
            (Layer::Iac, scan.iac.as_ref(), "scan.iac"),
        ];
        for (layer, section, name) in sections {
            let Some(section) = section else { continue };
            if !section.exclude.is_empty() {
                per_layer.insert(layer, compile(&section.exclude, name)?);
            }
        }
        Ok(Self { global, per_layer })
    }

    /// Whether `rel_path` (root-relative, POSIX separators) is excluded for
    /// `layer`: the global list applies to every layer, the layer list only
    /// to its own engines. Call it on file paths to skip them and on
    /// directory paths to prune the walk.
    pub fn is_excluded(&self, layer: Layer, rel_path: &str) -> bool {
        self.global.is_match(rel_path)
            || self
                .per_layer
                .get(&layer)
                .is_some_and(|set| set.is_match(rel_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter_excludes_nothing() {
        let filter = PathFilter::empty();
        assert!(!filter.is_excluded(Layer::Secrets, "uv.lock"));
        assert!(!filter.is_excluded(Layer::Sca, "src/main.rs"));
    }

    #[test]
    fn global_exclude_applies_to_all_layers() {
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "scan": { "exclude": ["vendor/**", "*.min.js"] }
        }))
        .unwrap();
        let filter = PathFilter::from_config(&cfg).unwrap();
        for layer in [Layer::Sca, Layer::Secrets, Layer::Iac] {
            assert!(filter.is_excluded(layer, "vendor/lib/x.js"));
            assert!(filter.is_excluded(layer, "dist/app.min.js"));
            assert!(!filter.is_excluded(layer, "src/app.js"));
        }
    }

    #[test]
    fn layer_exclude_extends_global_for_that_layer_only() {
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "scan": {
                "exclude": [".idea/**"],
                "secrets": { "exclude": ["**/*.lock"] }
            }
        }))
        .unwrap();
        let filter = PathFilter::from_config(&cfg).unwrap();
        // Layer-scoped: excluded for secrets, still visible to sca.
        assert!(filter.is_excluded(Layer::Secrets, "uv.lock"));
        assert!(filter.is_excluded(Layer::Secrets, "sub/Cargo.lock"));
        assert!(!filter.is_excluded(Layer::Sca, "uv.lock"));
        // Global: excluded everywhere.
        assert!(filter.is_excluded(Layer::Sca, ".idea/workspace.xml"));
        assert!(filter.is_excluded(Layer::Secrets, ".idea/workspace.xml"));
    }

    #[test]
    fn directory_path_match_supports_pruning() {
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "scan": { "exclude": [".venv", ".venv/**"] }
        }))
        .unwrap();
        let filter = PathFilter::from_config(&cfg).unwrap();
        // The dir itself matches (prune) and so does anything beneath it.
        assert!(filter.is_excluded(Layer::Secrets, ".venv"));
        assert!(filter.is_excluded(Layer::Secrets, ".venv/lib/site.py"));
    }

    #[test]
    fn invalid_glob_reports_pattern_and_section() {
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "scan": { "iac": { "exclude": ["a{b"] } }
        }))
        .unwrap();
        let err = PathFilter::from_config(&cfg).unwrap_err();
        assert_eq!(err.pattern, "a{b");
        assert_eq!(err.section, "scan.iac");
    }

    #[test]
    fn no_scan_section_means_empty_filter() {
        let cfg: Config = serde_json::from_value(serde_json::json!({})).unwrap();
        let filter = PathFilter::from_config(&cfg).unwrap();
        assert!(!filter.is_excluded(Layer::Iac, "main.tf"));
    }
}
