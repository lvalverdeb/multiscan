//! `SqliteStore` — the v1 backend (STO-001), writing to
//! `.multiscan/multiscan.db`. Migrations are forward-only and versioned via
//! SQLite's `PRAGMA user_version`; a database from a newer binary is refused,
//! not corrupted (STO-004).

use std::path::Path;

use chrono::{DateTime, Utc};
use multiscan_core::{Finding, FindingId};
use rusqlite::{Connection, OptionalExtension};

use crate::{FindingEvent, FindingEventKind, Store, StoreError, Suppression, UpsertStats};

/// Forward-only schema migrations. Index i (0-based) upgrades `user_version`
/// from i to i+1. **Never edit or reorder an existing entry** — only append;
/// existing databases have already run them (STO-004).
const MIGRATIONS: &[&str] = &[
    // v0 -> v1: base schema.
    r#"
    CREATE TABLE findings (
        finding_id   TEXT PRIMARY KEY,
        status       TEXT NOT NULL,
        risk_score   REAL NOT NULL,
        finding_json TEXT NOT NULL,
        first_seen   TEXT NOT NULL,
        last_seen    TEXT NOT NULL
    );
    CREATE TABLE finding_events (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id TEXT NOT NULL,
        at         TEXT NOT NULL,
        kind       TEXT NOT NULL,
        from_val   TEXT,
        to_val     TEXT
    );
    CREATE INDEX idx_events_finding ON finding_events(finding_id, id);
    CREATE TABLE baselines (
        name         TEXT NOT NULL,
        finding_id   TEXT NOT NULL,
        finding_json TEXT NOT NULL,
        PRIMARY KEY (name, finding_id)
    );
    CREATE TABLE suppressions (
        finding_id    TEXT PRIMARY KEY,
        justification TEXT NOT NULL,
        approver      TEXT NOT NULL,
        expires       TEXT NOT NULL,
        created_at    TEXT NOT NULL
    );
    "#,
];

/// Score changes below this are treated as noise, not a `ScoreChanged` event.
const SCORE_EPSILON: f64 = 0.001;

fn backend<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn serde<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Serialization(e.to_string())
}

/// SQLite-backed [`Store`].
pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    /// The highest schema version this binary understands.
    pub fn target_version() -> u32 {
        MIGRATIONS.len() as u32
    }

    /// Open (creating if needed) the database at `path`, running any pending
    /// forward migrations. Refuses a newer schema (STO-004).
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(backend)?;
        }
        let conn = Connection::open(path).map_err(backend)?;
        Self::from_connection(conn)
    }

    /// Open an in-memory SQLite database (distinct from [`crate::MemoryStore`];
    /// this exercises the real SQL path without touching disk).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(backend)?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self, StoreError> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(backend)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(backend)?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<(), StoreError> {
        let current: u32 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(backend)?;
        let target = Self::target_version();
        if current > target {
            return Err(StoreError::SchemaTooNew {
                found: current,
                supported: target,
            });
        }
        for (i, migration) in MIGRATIONS.iter().enumerate().skip(current as usize) {
            let tx = self.conn.transaction().map_err(backend)?;
            tx.execute_batch(migration).map_err(backend)?;
            // user_version can't be parameterized; the value is a trusted index.
            tx.pragma_update(None, "user_version", (i + 1) as i64)
                .map_err(backend)?;
            tx.commit().map_err(backend)?;
        }
        Ok(())
    }
}

impl SqliteStore {
    /// Read suppressions; `filter` keeps only those active after the given
    /// instant, `None` returns all (active and expired).
    fn read_suppressions(
        &self,
        filter: Option<DateTime<Utc>>,
    ) -> Result<Vec<Suppression>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT finding_id, justification, approver, expires FROM suppressions
                 ORDER BY finding_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(backend)?;
        let mut out = Vec::new();
        for row in rows {
            let (finding_id, justification, approver, expires) = row.map_err(backend)?;
            let expires = DateTime::parse_from_rfc3339(&expires)
                .map_err(serde)?
                .with_timezone(&Utc);
            let keep = match filter {
                Some(now) => expires > now,
                None => true,
            };
            if keep {
                out.push(Suppression {
                    finding_id,
                    justification,
                    approver,
                    expires,
                });
            }
        }
        Ok(out)
    }
}

fn kind_columns(kind: &FindingEventKind) -> (&'static str, Option<String>, Option<String>) {
    match kind {
        FindingEventKind::FirstSeen { status } => ("first_seen", None, Some(status.clone())),
        FindingEventKind::StatusChanged { from, to } => {
            ("status_changed", Some(from.clone()), Some(to.clone()))
        }
        FindingEventKind::ScoreChanged { from, to } => (
            "score_changed",
            Some(from.to_string()),
            Some(to.to_string()),
        ),
    }
}

fn kind_from_columns(
    kind: &str,
    from_val: Option<String>,
    to_val: Option<String>,
) -> Result<FindingEventKind, StoreError> {
    let parse = |v: Option<String>| v.unwrap_or_default();
    Ok(match kind {
        "first_seen" => FindingEventKind::FirstSeen {
            status: parse(to_val),
        },
        "status_changed" => FindingEventKind::StatusChanged {
            from: parse(from_val),
            to: parse(to_val),
        },
        "score_changed" => FindingEventKind::ScoreChanged {
            from: parse(from_val).parse().unwrap_or(0.0),
            to: parse(to_val).parse().unwrap_or(0.0),
        },
        other => {
            return Err(StoreError::Serialization(format!(
                "unknown event kind {other}"
            )))
        }
    })
}

impl Store for SqliteStore {
    fn upsert_findings(
        &mut self,
        findings: &[Finding],
        now: DateTime<Utc>,
    ) -> Result<UpsertStats, StoreError> {
        let now_rfc = now.to_rfc3339();
        let tx = self.conn.transaction().map_err(backend)?;
        let mut stats = UpsertStats::default();

        for finding in findings {
            let id = finding.finding_id.0.clone();
            let status = format!("{:?}", finding.status);
            let score = finding.risk_score;
            let json = serde_json::to_string(finding).map_err(serde)?;

            let existing: Option<(String, f64)> = tx
                .query_row(
                    "SELECT status, risk_score FROM findings WHERE finding_id = ?1",
                    [&id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(backend)?;

            let mut events: Vec<FindingEventKind> = Vec::new();
            match existing {
                None => {
                    events.push(FindingEventKind::FirstSeen {
                        status: status.clone(),
                    });
                    tx.execute(
                        "INSERT INTO findings (finding_id, status, risk_score, finding_json, first_seen, last_seen)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                        rusqlite::params![id, status, score, json, now_rfc],
                    )
                    .map_err(backend)?;
                    stats.new += 1;
                }
                Some((old_status, old_score)) => {
                    if old_status != status {
                        events.push(FindingEventKind::StatusChanged {
                            from: old_status,
                            to: status.clone(),
                        });
                    }
                    if (old_score - score).abs() > SCORE_EPSILON {
                        events.push(FindingEventKind::ScoreChanged {
                            from: old_score,
                            to: score,
                        });
                    }
                    if events.is_empty() {
                        stats.unchanged += 1;
                    } else {
                        stats.updated += 1;
                    }
                    tx.execute(
                        "UPDATE findings SET status = ?2, risk_score = ?3, finding_json = ?4, last_seen = ?5
                         WHERE finding_id = ?1",
                        rusqlite::params![id, status, score, json, now_rfc],
                    )
                    .map_err(backend)?;
                }
            }

            for kind in &events {
                let (kind_str, from_val, to_val) = kind_columns(kind);
                tx.execute(
                    "INSERT INTO finding_events (finding_id, at, kind, from_val, to_val)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![id, now_rfc, kind_str, from_val, to_val],
                )
                .map_err(backend)?;
            }
        }

        tx.commit().map_err(backend)?;
        Ok(stats)
    }

    fn load_baseline(&self, name: &str) -> Result<Vec<Finding>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT finding_json FROM baselines WHERE name = ?1 ORDER BY finding_id")
            .map_err(backend)?;
        let rows = stmt
            .query_map([name], |row| row.get::<_, String>(0))
            .map_err(backend)?;
        let mut findings = Vec::new();
        for row in rows {
            let json = row.map_err(backend)?;
            findings.push(serde_json::from_str(&json).map_err(serde)?);
        }
        Ok(findings)
    }

    fn save_baseline(&mut self, name: &str, findings: &[Finding]) -> Result<(), StoreError> {
        let tx = self.conn.transaction().map_err(backend)?;
        tx.execute("DELETE FROM baselines WHERE name = ?1", [name])
            .map_err(backend)?;
        for finding in findings {
            let json = serde_json::to_string(finding).map_err(serde)?;
            tx.execute(
                "INSERT INTO baselines (name, finding_id, finding_json) VALUES (?1, ?2, ?3)",
                rusqlite::params![name, finding.finding_id.0, json],
            )
            .map_err(backend)?;
        }
        tx.commit().map_err(backend)?;
        Ok(())
    }

    fn history(&self, finding_id: &FindingId) -> Result<Vec<FindingEvent>, StoreError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT at, kind, from_val, to_val FROM finding_events
                 WHERE finding_id = ?1 ORDER BY id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([&finding_id.0], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })
            .map_err(backend)?;
        let mut events = Vec::new();
        for row in rows {
            let (at, kind, from_val, to_val) = row.map_err(backend)?;
            let at = DateTime::parse_from_rfc3339(&at)
                .map_err(serde)?
                .with_timezone(&Utc);
            events.push(FindingEvent {
                finding_id: finding_id.0.clone(),
                at,
                kind: kind_from_columns(&kind, from_val, to_val)?,
            });
        }
        Ok(events)
    }

    fn all_findings(&self) -> Result<Vec<Finding>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT finding_json FROM findings ORDER BY finding_id")
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(backend)?;
        let mut findings = Vec::new();
        for row in rows {
            findings.push(serde_json::from_str(&row.map_err(backend)?).map_err(serde)?);
        }
        Ok(findings)
    }

    fn all_suppressions(&self) -> Result<Vec<Suppression>, StoreError> {
        self.read_suppressions(None)
    }

    fn active_suppressions(&self, now: DateTime<Utc>) -> Result<Vec<Suppression>, StoreError> {
        self.read_suppressions(Some(now))
    }

    fn put_suppression(&mut self, suppression: &Suppression) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO suppressions (finding_id, justification, approver, expires, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(finding_id) DO UPDATE SET
                   justification = excluded.justification,
                   approver = excluded.approver,
                   expires = excluded.expires",
                rusqlite::params![
                    suppression.finding_id,
                    suppression.justification,
                    suppression.approver,
                    suppression.expires.to_rfc3339(),
                    Utc::now().to_rfc3339(),
                ],
            )
            .map_err(backend)?;
        Ok(())
    }
}
