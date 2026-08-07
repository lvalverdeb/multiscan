//! Structural pattern matching over source code (spec 7.5).
//!
//! v1 shipped the scaffold and [`structural_hash`] only (`T-604`). `T-701` adds
//! the language-independent core: the [`tree`] both front-ends lower into, the
//! MS-PAT-1 [`pattern`] representation, the [`matcher`], and [`rules`] pack
//! loading. Language front-ends — the parsers that turn real source and leaf
//! pattern text into these types — arrive with `T-702` (ADR 0015).
//!
//! **NG-2 stands permanently: structural matching only, no taint or dataflow
//! analysis.** [`pattern::PatternExpr`] has no variant that could express it.
//!
//! The contract this implements is `docs/ms-pat-1.md`.

pub mod matcher;
pub mod pattern;
pub mod rules;
pub mod tree;

use multiscan_core::{EngineManifest, FindingClass, Layer, NetworkImpact, Severity};
use multiscan_engine::{
    Applicability, Engine, EngineError, EngineOutcome, FindingSink, ScanContext,
};

use crate::tree::Node;

/// Domain separator for the structural hash. Bumping it changes every
/// `StructuralPattern` finding_id, so it is frozen (cf. dedup's identity
/// encoding).
const STRUCTURAL_DOMAIN: &[u8] = b"multiscan:structural_hash:v1";

/// Hash the *shape* of a code fragment: its canonical node kinds plus its
/// normalized identifiers — never raw line numbers or literal text (spec
/// 7.7.2, amended by ADR 0016). Two fragments that differ only in whitespace,
/// line position, or (with normalization) identifier spelling produce the same
/// hash, so a `StructuralPattern` finding is stable across cosmetic edits.
///
/// Kinds come from [`tree::Kind`] — MultiScan's own closed vocabulary, not a
/// parser's — so identity survives a parser upgrade or replacement
/// (ADR 0015). Prefer [`structural_hash_of`], which derives both arguments
/// from a matched subtree in the frozen pre-order form.
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

/// Hash a matched subtree in the frozen form: pre-order canonical kinds plus
/// normalized identifiers, spans excluded (`docs/ms-pat-1.md` §5).
///
/// This is the `structural_hash` component of the `StructuralPattern` identity
/// tuple, so **reformatting a file does not change the resulting
/// `finding_id`** (`SAST-002`). Changing what this function feeds the hash
/// invalidates every user's baselines and suppressions — a stop-and-ask change.
pub fn structural_hash_of(node: &Node) -> String {
    let (kinds, names) = node.structural_parts();
    structural_hash(&kinds, &names)
}

/// The SAST engine. Still `NotApplicable` until `T-702` supplies the language
/// front-ends that can turn source into a [`tree::Node`] — with no parser there
/// is nothing to match against, and reporting `Complete` over zero files would
/// wrongly close findings (§7.7.4).
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
        // T-701 ships the matcher core but no front-end can parse source yet;
        // the engine stays inert until T-702. Cheap and I/O-free either way.
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
