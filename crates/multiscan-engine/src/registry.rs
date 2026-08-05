//! Engine registry and parallel dispatch (spec 6.2).

use rayon::prelude::*;

use crate::{
    Applicability, Engine, EngineError, EngineOutcome, FindingSink, RawFinding, ScanContext,
    SinkError,
};

/// Everything one engine produced in one Scan. Emit order within `findings`
/// is meaningless (spec 6.2) — rendering sorts (CLI-003).
pub struct EngineRun {
    /// Manifest id of the engine.
    pub engine_id: String,
    /// Outcome or typed failure. `Partial` and `Err` both force exit ≥ 3
    /// (ENG-002, FR-015); other engines' findings are still reported.
    pub outcome: Result<EngineOutcome, EngineError>,
    /// Findings streamed during the run.
    pub findings: Vec<RawFinding>,
}

/// Collects emissions for one engine run.
#[derive(Default)]
struct VecSink {
    findings: Vec<RawFinding>,
}

impl FindingSink for VecSink {
    fn emit(&mut self, finding: RawFinding) -> Result<(), SinkError> {
        self.findings.push(finding);
        Ok(())
    }

    fn progress(&mut self, _done: u64, _total: Option<u64>) {
        // Progress rendering is a CLI concern; the registry-level sink drops it.
    }
}

/// Holds the registered engines and dispatches applicable ones in parallel.
#[derive(Default)]
pub struct Registry {
    engines: Vec<Box<dyn Engine>>,
}

impl Registry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an engine.
    pub fn register(&mut self, engine: Box<dyn Engine>) {
        self.engines.push(engine);
    }

    /// Engines whose `applicable()` accepts this context and whose layers
    /// intersect the context's selected layers.
    fn applicable<'a>(&'a self, ctx: &ScanContext) -> Vec<&'a dyn Engine> {
        self.engines
            .iter()
            .map(AsRef::as_ref)
            .filter(|e| {
                e.manifest()
                    .layers
                    .iter()
                    .any(|layer| ctx.layers.contains(layer))
            })
            .filter(|e| e.applicable(ctx) == Applicability::Applicable)
            .collect()
    }

    /// Run all applicable engines on the rayon pool and collect their runs,
    /// sorted by engine id (emit order is never meaningful, DET-002).
    pub fn run(&self, ctx: &ScanContext) -> Vec<EngineRun> {
        let mut runs: Vec<EngineRun> = self
            .applicable(ctx)
            .into_par_iter()
            .map(|engine| {
                let mut sink = VecSink::default();
                let outcome = engine.scan(ctx, &mut sink);
                EngineRun {
                    engine_id: engine.manifest().id.clone(),
                    outcome,
                    findings: sink.findings,
                }
            })
            .collect();
        runs.sort_by(|a, b| a.engine_id.cmp(&b.engine_id));
        runs
    }
}
