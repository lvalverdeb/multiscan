//! Designated test fakes (CLAUDE.md: the only sanctioned test doubles).
//! Used by this crate's tests, the CLI walking skeleton, and the determinism
//! harness. Not part of any production scan path — production engines live
//! under `crates/engines/`.

use multiscan_core::{
    Asset, AssetKind, Confidence, EngineManifest, IdentityKey, Location, NetworkImpact, RawFinding,
    Severity,
};

use crate::{Applicability, Engine, EngineError, EngineOutcome, FindingSink, ScanContext};

fn manifest(id: &str) -> EngineManifest {
    EngineManifest {
        id: id.to_string(),
        version: "0.0.0-testkit".to_string(),
        finding_classes: vec![multiscan_core::FindingClass::IacMisconfiguration],
        layers: vec![multiscan_core::Layer::Iac],
        network_impact: NetworkImpact::ReadOnly,
        requires_authorization: false,
        rule_set: None,
        severity_map: [("test".to_string(), Severity::Medium)]
            .into_iter()
            .collect(),
    }
}

/// An engine that is never applicable — mirrors the v1 SAST scaffold (spec 7.5).
pub struct NullEngine {
    manifest: EngineManifest,
}

impl NullEngine {
    /// Create the fake.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            manifest: manifest("testkit.null"),
        }
    }
}

impl Engine for NullEngine {
    fn manifest(&self) -> &EngineManifest {
        &self.manifest
    }

    fn applicable(&self, _ctx: &ScanContext) -> Applicability {
        Applicability::NotApplicable
    }

    fn scan(
        &self,
        _ctx: &ScanContext,
        _sink: &mut dyn FindingSink,
    ) -> Result<EngineOutcome, EngineError> {
        Err(EngineError::Failed(
            "NullEngine must never be scanned".to_string(),
        ))
    }
}

/// Deterministic fixture engine: emits `count` synthetic findings, checks
/// cancel/deadline between units, and can be configured to end `Partial` or
/// fail — everything the pipeline plumbing needs exercised.
pub struct FixtureEngine {
    manifest: EngineManifest,
    count: u64,
    /// Force a `Partial` outcome after emitting everything.
    force_partial: Option<String>,
    /// Force a hard failure before emitting anything.
    force_error: bool,
}

impl FixtureEngine {
    /// Fixture emitting `count` findings then `Complete`.
    pub fn new(id: &str, count: u64) -> Self {
        Self {
            manifest: manifest(id),
            count,
            force_partial: None,
            force_error: false,
        }
    }

    /// Same, but the outcome is `Partial` with the given reason (ENG-002 path).
    pub fn partial(id: &str, count: u64, reason: &str) -> Self {
        Self {
            force_partial: Some(reason.to_string()),
            ..Self::new(id, count)
        }
    }

    /// Fixture that fails outright (FR-015 path).
    pub fn failing(id: &str) -> Self {
        Self {
            force_error: true,
            ..Self::new(id, 0)
        }
    }

    /// The deterministic finding this fixture emits for unit `index`.
    pub fn finding(&self, index: u64) -> RawFinding {
        RawFinding {
            identity: IdentityKey::IacMisconfiguration {
                policy_id: format!("TESTKIT-{index:03}"),
                path: format!("fixtures/resource-{index:03}.tf"),
                resource_address: format!("test_resource.r{index:03}"),
            },
            title: format!("Fixture finding {index:03}"),
            description: None,
            severity: if index % 2 == 0 {
                Severity::Medium
            } else {
                Severity::High
            },
            confidence: Confidence::Heuristic,
            asset: Asset {
                kind: AssetKind::File,
                identifier: format!("fixtures/resource-{index:03}.tf"),
            },
            location: Location {
                path: format!("fixtures/resource-{index:03}.tf"),
                line: Some(1),
            },
            evidence: vec![],
            rule_id: Some(format!("TESTKIT-{index:03}")),
            remediation: None,
            cwe: vec![],
        }
    }
}

impl Engine for FixtureEngine {
    fn manifest(&self) -> &EngineManifest {
        &self.manifest
    }

    fn applicable(&self, _ctx: &ScanContext) -> Applicability {
        Applicability::Applicable
    }

    fn scan(
        &self,
        ctx: &ScanContext,
        sink: &mut dyn FindingSink,
    ) -> Result<EngineOutcome, EngineError> {
        if self.force_error {
            return Err(EngineError::Failed("forced failure".to_string()));
        }
        let mut emitted = 0;
        for index in 0..self.count {
            // Cancellation/deadline check between units of work (spec 6.1).
            if ctx.should_stop() {
                return Ok(EngineOutcome::Partial {
                    units_scanned: emitted,
                    reason: "cancelled or past deadline".to_string(),
                });
            }
            sink.emit(self.finding(index))
                .map_err(|e| EngineError::Failed(e.to_string()))?;
            emitted += 1;
            sink.progress(emitted, Some(self.count));
        }
        match &self.force_partial {
            Some(reason) => Ok(EngineOutcome::Partial {
                units_scanned: emitted,
                reason: reason.clone(),
            }),
            None => Ok(EngineOutcome::Complete {
                units_scanned: emitted,
            }),
        }
    }
}

/// Build a minimal `ScanContext` for tests and the walking skeleton.
pub fn test_context(layers: Vec<multiscan_core::Layer>) -> ScanContext {
    ScanContext {
        root: std::path::PathBuf::from("."),
        config: multiscan_core::Config {
            scan: None,
            gate: None,
            risk: None,
            feeds: None,
            rules: None,
            suppress: vec![],
        },
        excludes: crate::PathFilter::empty(),
        profile: multiscan_core::Profile::Standard,
        layers,
        feed_snapshot_id: None,
        feed_cache_dir: None,
        authorization: None,
        cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        deadline: None,
        started_at: "2026-01-01T00:00:00Z".to_string(),
    }
}
