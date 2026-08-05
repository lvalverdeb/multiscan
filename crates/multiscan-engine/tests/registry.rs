//! T-102 acceptance: applicability filtering, lossless parallel emission,
//! Partial/failure propagation, cancel and deadline honoured (spec 6, FR-015).

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use multiscan_core::Layer;
use multiscan_engine::testkit::{test_context, FixtureEngine, NullEngine};
use multiscan_engine::{EngineOutcome, Registry};

fn registry_with(engines: Vec<Box<dyn multiscan_engine::Engine>>) -> Registry {
    let mut registry = Registry::new();
    for engine in engines {
        registry.register(engine);
    }
    registry
}

#[test]
fn not_applicable_engines_do_not_run() {
    let registry = registry_with(vec![
        Box::new(NullEngine::new()),
        Box::new(FixtureEngine::new("testkit.fixture", 3)),
    ]);
    let runs = registry.run(&test_context(vec![Layer::Iac]));
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].engine_id, "testkit.fixture");
    assert_eq!(runs[0].findings.len(), 3);
}

#[test]
fn layer_filter_excludes_engines() {
    let registry = registry_with(vec![Box::new(FixtureEngine::new("testkit.fixture", 3))]);
    // Fixture engine declares the iac layer; a secrets-only scan skips it.
    let runs = registry.run(&test_context(vec![Layer::Secrets]));
    assert!(runs.is_empty());
}

/// Emission is lossless when many engines run concurrently on the rayon pool.
#[test]
fn parallel_emission_is_lossless() {
    let engines: Vec<Box<dyn multiscan_engine::Engine>> = (0..8)
        .map(|i| {
            Box::new(FixtureEngine::new(&format!("testkit.fixture{i}"), 500))
                as Box<dyn multiscan_engine::Engine>
        })
        .collect();
    let registry = registry_with(engines);
    let runs = registry.run(&test_context(vec![Layer::Iac]));
    assert_eq!(runs.len(), 8);
    for run in &runs {
        assert_eq!(run.findings.len(), 500, "{} lost findings", run.engine_id);
        assert!(matches!(
            run.outcome,
            Ok(EngineOutcome::Complete { units_scanned: 500 })
        ));
    }
    // Runs come back sorted by engine id regardless of completion order.
    let ids: Vec<_> = runs.iter().map(|r| r.engine_id.clone()).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
}

/// FR-015: one engine failing must not suppress the others' findings.
#[test]
fn failure_is_isolated() {
    let registry = registry_with(vec![
        Box::new(FixtureEngine::failing("testkit.bad")),
        Box::new(FixtureEngine::new("testkit.good", 2)),
    ]);
    let runs = registry.run(&test_context(vec![Layer::Iac]));
    assert_eq!(runs.len(), 2);
    assert!(runs.iter().any(|r| r.outcome.is_err()));
    let good = runs.iter().find(|r| r.engine_id == "testkit.good").unwrap();
    assert_eq!(good.findings.len(), 2);
}

/// ENG-002: Partial propagates with its reason.
#[test]
fn partial_outcome_propagates() {
    let registry = registry_with(vec![Box::new(FixtureEngine::partial(
        "testkit.partial",
        2,
        "lockfile unparseable",
    ))]);
    let runs = registry.run(&test_context(vec![Layer::Iac]));
    match &runs[0].outcome {
        Ok(EngineOutcome::Partial {
            units_scanned,
            reason,
        }) => {
            assert_eq!(*units_scanned, 2);
            assert_eq!(reason, "lockfile unparseable");
        }
        other => panic!("expected Partial, got {other:?}"),
    }
}

/// Pre-set cancellation stops the engine before any unit of work.
#[test]
fn cancel_yields_partial() {
    let ctx = test_context(vec![Layer::Iac]);
    ctx.cancel.store(true, Ordering::Relaxed);
    let registry = registry_with(vec![Box::new(FixtureEngine::new("testkit.fixture", 1000))]);
    let runs = registry.run(&ctx);
    match &runs[0].outcome {
        Ok(EngineOutcome::Partial { units_scanned, .. }) => assert_eq!(*units_scanned, 0),
        other => panic!("expected Partial on cancel, got {other:?}"),
    }
}

/// An already-elapsed deadline stops the engine before any unit of work.
#[test]
fn deadline_yields_partial() {
    let mut ctx = test_context(vec![Layer::Iac]);
    ctx.deadline = Some(Instant::now() - Duration::from_millis(1));
    let registry = registry_with(vec![Box::new(FixtureEngine::new("testkit.fixture", 1000))]);
    let runs = registry.run(&ctx);
    match &runs[0].outcome {
        Ok(EngineOutcome::Partial { units_scanned, .. }) => assert_eq!(*units_scanned, 0),
        other => panic!("expected Partial on deadline, got {other:?}"),
    }
}
