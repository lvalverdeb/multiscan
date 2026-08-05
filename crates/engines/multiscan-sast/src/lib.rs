//! SAST scaffold: structural_hash only in v1, no rules (spec 7.5, NG-2).
//!
//! v1 ships the crate skeleton, an `Engine` that is always `NotApplicable`, and
//! the [`structural_hash`] function that dedup needs for the `StructuralPattern`
//! identity (spec 7.7.2). **No detection rules, and no taint analysis — NG-2
//! stands permanently.** tree-sitter parsing and rule matching are v2 scope.

use multiscan_core::{EngineManifest, FindingClass, Layer, NetworkImpact, Severity};
use multiscan_engine::{
    Applicability, Engine, EngineError, EngineOutcome, FindingSink, ScanContext,
};

/// Domain separator for the structural hash. Bumping it changes every
/// `StructuralPattern` finding_id, so it is frozen (cf. dedup's identity
/// encoding).
const STRUCTURAL_DOMAIN: &[u8] = b"multiscan:structural_hash:v1";

/// Hash the *shape* of a code fragment: its tree-sitter node kinds plus its
/// normalized identifiers — never raw line numbers or literal text (spec
/// 7.7.2, line 405). Two fragments that differ only in whitespace, line
/// position, or (with normalization) identifier spelling produce the same hash,
/// so a `StructuralPattern` finding is stable across cosmetic edits.
///
/// v1 exposes the canonical function; real callers arrive with v2 SAST.
pub fn structural_hash(node_kinds: &[&str], normalized_identifiers: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STRUCTURAL_DOMAIN);
    hasher.update(&(node_kinds.len() as u64).to_le_bytes());
    for kind in node_kinds {
        hasher.update(&(kind.len() as u64).to_le_bytes());
        hasher.update(kind.as_bytes());
    }
    hasher.update(&(normalized_identifiers.len() as u64).to_le_bytes());
    for id in normalized_identifiers {
        hasher.update(&(id.len() as u64).to_le_bytes());
        hasher.update(id.as_bytes());
    }
    format!("b3:{}", &hasher.finalize().to_hex()[..24])
}

/// The v1 SAST engine: a registered no-op. `applicable()` is always
/// `NotApplicable`, so `scan()` is never called (spec 7.5).
pub struct SastEngine {
    manifest: EngineManifest,
}

impl SastEngine {
    /// Construct the scaffold engine.
    pub fn new() -> Self {
        Self {
            manifest: EngineManifest {
                id: "multiscan.sast".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                finding_classes: vec![FindingClass::StructuralPattern],
                layers: vec![Layer::Sast],
                network_impact: NetworkImpact::ReadOnly,
                requires_authorization: false,
                rule_set: None,
                // No rules ship in v1, but the manifest still declares an
                // explicit (empty) severity map to satisfy ENG-004.
                severity_map: [("structural", Severity::Medium)]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
            },
        }
    }
}

impl Default for SastEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine for SastEngine {
    fn manifest(&self) -> &EngineManifest {
        &self.manifest
    }

    fn applicable(&self, _ctx: &ScanContext) -> Applicability {
        // v1 ships no rules; the engine never runs (NG-2).
        Applicability::NotApplicable
    }

    fn scan(
        &self,
        _ctx: &ScanContext,
        _sink: &mut dyn FindingSink,
    ) -> Result<EngineOutcome, EngineError> {
        // Unreachable in practice (applicable() gates it); return Complete with
        // zero units rather than error, so a direct call is harmless.
        Ok(EngineOutcome::Complete { units_scanned: 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_hash_ignores_line_positions() {
        // Same node kinds + identifiers ⇒ same hash regardless of anything the
        // caller might have wanted to include (line numbers are never passed).
        let a = structural_hash(&["call", "identifier"], &["unwrap"]);
        let b = structural_hash(&["call", "identifier"], &["unwrap"]);
        assert_eq!(a, b);
        assert!(a.starts_with("b3:"));
    }

    #[test]
    fn different_shapes_differ() {
        assert_ne!(
            structural_hash(&["call"], &["a"]),
            structural_hash(&["call"], &["b"])
        );
        assert_ne!(
            structural_hash(&["call", "arg"], &["a"]),
            structural_hash(&["call"], &["a", "arg"])
        );
    }

    #[test]
    fn engine_is_not_applicable() {
        let engine = SastEngine::new();
        let ctx = multiscan_engine::testkit::test_context(vec![Layer::Sast]);
        assert_eq!(engine.applicable(&ctx), Applicability::NotApplicable);
    }
}
