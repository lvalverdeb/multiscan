//! In-memory [`Store`] for tests (STO-001). Mirrors [`crate::SqliteStore`]
//! semantics — event-sourced history, named baselines, suppressions — without
//! touching disk.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use multiscan_core::{Finding, FindingId};

use crate::{FindingEvent, FindingEventKind, Store, StoreError, Suppression, UpsertStats};

const SCORE_EPSILON: f64 = 0.001;

#[derive(Clone)]
struct Record {
    status: String,
    risk_score: f64,
}

/// In-memory store. `BTreeMap` keeps iteration deterministic (DET-001).
#[derive(Default)]
pub struct MemoryStore {
    findings: BTreeMap<String, Record>,
    events: BTreeMap<String, Vec<FindingEvent>>,
    baselines: BTreeMap<String, Vec<Finding>>,
    suppressions: BTreeMap<String, Suppression>,
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn upsert_findings(
        &mut self,
        findings: &[Finding],
        now: DateTime<Utc>,
    ) -> Result<UpsertStats, StoreError> {
        let mut stats = UpsertStats::default();
        for finding in findings {
            let id = finding.finding_id.0.clone();
            let status = format!("{:?}", finding.status);
            let score = finding.risk_score;

            let mut kinds: Vec<FindingEventKind> = Vec::new();
            match self.findings.get(&id) {
                None => {
                    kinds.push(FindingEventKind::FirstSeen {
                        status: status.clone(),
                    });
                    stats.new += 1;
                }
                Some(existing) => {
                    if existing.status != status {
                        kinds.push(FindingEventKind::StatusChanged {
                            from: existing.status.clone(),
                            to: status.clone(),
                        });
                    }
                    if (existing.risk_score - score).abs() > SCORE_EPSILON {
                        kinds.push(FindingEventKind::ScoreChanged {
                            from: existing.risk_score,
                            to: score,
                        });
                    }
                    if kinds.is_empty() {
                        stats.unchanged += 1;
                    } else {
                        stats.updated += 1;
                    }
                }
            }

            self.findings.insert(
                id.clone(),
                Record {
                    status: status.clone(),
                    risk_score: score,
                },
            );
            let log = self.events.entry(id.clone()).or_default();
            for kind in kinds {
                log.push(FindingEvent {
                    finding_id: id.clone(),
                    at: now,
                    kind,
                });
            }
        }
        Ok(stats)
    }

    fn load_baseline(&self, name: &str) -> Result<Vec<Finding>, StoreError> {
        Ok(self.baselines.get(name).cloned().unwrap_or_default())
    }

    fn save_baseline(&mut self, name: &str, findings: &[Finding]) -> Result<(), StoreError> {
        let mut sorted = findings.to_vec();
        sorted.sort_by(|a, b| a.finding_id.0.cmp(&b.finding_id.0));
        self.baselines.insert(name.to_string(), sorted);
        Ok(())
    }

    fn history(&self, finding_id: &FindingId) -> Result<Vec<FindingEvent>, StoreError> {
        Ok(self.events.get(&finding_id.0).cloned().unwrap_or_default())
    }

    fn active_suppressions(&self, now: DateTime<Utc>) -> Result<Vec<Suppression>, StoreError> {
        Ok(self
            .suppressions
            .values()
            .filter(|s| s.expires > now)
            .cloned()
            .collect())
    }

    fn put_suppression(&mut self, suppression: &Suppression) -> Result<(), StoreError> {
        self.suppressions
            .insert(suppression.finding_id.clone(), suppression.clone());
        Ok(())
    }
}
