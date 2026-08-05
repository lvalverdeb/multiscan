//! Append-only authorization audit log (SEC-008). Every authorize/deny
//! decision is recorded with its deciding rule. If the log cannot be written,
//! the guard fails closed — a security audit trail that silently drops entries
//! is worse than refusing to proceed.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::decision::Decision;

/// Append-only audit log.
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Open (creating) the audit log at `path`.
    pub fn open(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }

    /// Record a decision. `at` is the injected timestamp (RFC 3339). Returns an
    /// error if the entry could not be durably appended, so the caller can fail
    /// closed (SEC-008).
    pub fn record(
        &self,
        at: &str,
        authorization_id: &str,
        target: &str,
        method: &str,
        decision: &Decision,
    ) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        // One line per decision: timestamp, auth id, method, target, rule.
        writeln!(
            file,
            "{at}\t{authorization_id}\t{method}\t{target}\t{}",
            decision.rule()
        )?;
        file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{Decision, Denied};

    #[test]
    fn records_allow_and_deny_with_rule() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".multiscan/audit.log");
        let log = AuditLog::open(&path);
        log.record(
            "2026-08-05T00:00:00Z",
            "auth-1",
            "staging.acme.com",
            "GET",
            &Decision::Allowed {
                matched_pattern: "*.acme.com".into(),
            },
        )
        .unwrap();
        log.record(
            "2026-08-05T00:00:01Z",
            "auth-1",
            "evil.com",
            "GET",
            &Decision::Denied(Denied::NotIncluded("evil.com".into())),
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("allow: matched include `*.acme.com`"));
        assert!(lines[1].contains("deny: host `evil.com` matches no include"));
    }
}
