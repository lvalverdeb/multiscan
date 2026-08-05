//! T-301 acceptance: event-sourced history (STO-002), forward-only migrations
//! that refuse a newer schema (STO-004), baselines, suppressions, and
//! Memory/Sqlite parity (STO-001).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{TimeZone, Utc};
use multiscan_core::{
    Asset, AssetKind, Confidence, Finding, FindingId, FindingStatus, IdentityKey, Location,
    ScoreExplanation, ScoreFactors, Severity,
};
use multiscan_store::{
    FindingEventKind, MemoryStore, SqliteStore, Store, Suppression, UpsertStats,
};

fn finding(id: &str, score: f64, status: FindingStatus) -> Finding {
    Finding {
        finding_id: FindingId(id.to_string()),
        identity: IdentityKey::IacMisconfiguration {
            policy_id: "cis-1".into(),
            path: "main.tf".into(),
            resource_address: "aws_s3_bucket.a".into(),
        },
        title: "t".into(),
        description: None,
        severity: Severity::High,
        confidence: Confidence::Corroborated,
        status,
        risk_score: score,
        score_explanation: ScoreExplanation {
            formula_version: "1".into(),
            feed_snapshot_id: None,
            factors: ScoreFactors {
                severity_base: 0.75,
                exposure: 0.7,
                exploitability: 0.55,
                confidence: 0.85,
                asset_criticality: 1.0,
            },
            raw_product: 0.24,
            defaults_applied: vec![],
        },
        asset: Asset {
            kind: AssetKind::File,
            identifier: "main.tf".into(),
        },
        location: Location {
            path: "main.tf".into(),
            line: None,
        },
        evidence: vec![],
        sources: vec![],
        remediation: None,
        cwe: vec![],
    }
}

/// Run the same behavioural suite against any Store impl (STO-001 parity).
fn exercise(store: &mut dyn Store) {
    let t0 = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
    let t1 = Utc.with_ymd_and_hms(2026, 8, 2, 0, 0, 0).unwrap();
    let t2 = Utc.with_ymd_and_hms(2026, 8, 3, 0, 0, 0).unwrap();

    // First sight → one FirstSeen event.
    let stats = store
        .upsert_findings(&[finding("f1", 40.0, FindingStatus::Open)], t0)
        .unwrap();
    assert_eq!(
        stats,
        UpsertStats {
            new: 1,
            updated: 0,
            unchanged: 0
        }
    );

    // Re-scan unchanged → no new event.
    let stats = store
        .upsert_findings(&[finding("f1", 40.0, FindingStatus::Open)], t1)
        .unwrap();
    assert_eq!(stats.unchanged, 1);

    // Score change → ScoreChanged appended, old event NOT overwritten (STO-002).
    let stats = store
        .upsert_findings(&[finding("f1", 82.4, FindingStatus::Open)], t2)
        .unwrap();
    assert_eq!(stats.updated, 1);

    let history = store.history(&FindingId("f1".into())).unwrap();
    assert_eq!(history.len(), 2, "FirstSeen + ScoreChanged, append-only");
    assert!(matches!(
        history[0].kind,
        FindingEventKind::FirstSeen { .. }
    ));
    match &history[1].kind {
        FindingEventKind::ScoreChanged { from, to } => {
            assert!((*from - 40.0).abs() < 1e-9);
            assert!((*to - 82.4).abs() < 1e-9);
        }
        other => panic!("expected ScoreChanged, got {other:?}"),
    }
    assert_eq!(history[1].at, t2);

    // Status transition → StatusChanged appended.
    store
        .upsert_findings(&[finding("f1", 82.4, FindingStatus::Fixed)], t2)
        .unwrap();
    let history = store.history(&FindingId("f1".into())).unwrap();
    assert_eq!(history.len(), 3);
    assert!(matches!(
        history[2].kind,
        FindingEventKind::StatusChanged { .. }
    ));

    // Baselines round-trip.
    store
        .save_baseline("main", &[finding("f1", 82.4, FindingStatus::Open)])
        .unwrap();
    let loaded = store.load_baseline("main").unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].finding_id.0, "f1");
    assert!(store.load_baseline("absent").unwrap().is_empty());

    // Suppressions: active filtering by `now` (FR-014).
    store
        .put_suppression(&Suppression {
            finding_id: "f1".into(),
            justification: "vendored".into(),
            approver: "sec".into(),
            expires: Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0).unwrap(),
        })
        .unwrap();
    let before = Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap();
    let after = Utc.with_ymd_and_hms(2026, 9, 15, 0, 0, 0).unwrap();
    assert_eq!(store.active_suppressions(before).unwrap().len(), 1);
    assert!(store.active_suppressions(after).unwrap().is_empty());
}

#[test]
fn memory_store_behaviour() {
    let mut store = MemoryStore::new();
    exercise(&mut store);
}

#[test]
fn sqlite_store_behaviour() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    exercise(&mut store);
}

/// STO-004: a database written by a newer binary is refused, not corrupted.
#[test]
fn refuses_newer_schema() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("multiscan.db");
    {
        let store = SqliteStore::open(&path).unwrap();
        drop(store);
    }
    // Simulate a future binary bumping user_version beyond what we support.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", 999i64).unwrap();
    }
    match SqliteStore::open(&path) {
        Err(multiscan_store::StoreError::SchemaTooNew { found: 999, .. }) => {}
        Err(other) => panic!("expected SchemaTooNew, got {other:?}"),
        Ok(_) => panic!("expected refusal of a newer schema (STO-004)"),
    }
}

/// Migrations are idempotent: opening an already-migrated DB is a no-op.
#[test]
fn reopening_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("multiscan.db");
    let now = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
    {
        let mut store = SqliteStore::open(&path).unwrap();
        store
            .upsert_findings(&[finding("f1", 40.0, FindingStatus::Open)], now)
            .unwrap();
    }
    // Reopen: data survives, no migration error.
    let store = SqliteStore::open(&path).unwrap();
    let history = store.history(&FindingId("f1".into())).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(SqliteStore::target_version(), 1);
}
