//! Exit codes (spec 4.4). Code 3 is never conflated with 1 (CLI-005): a CI
//! pipeline must distinguish "you have vulnerabilities" from "the scanner
//! broke".

/// Process exit codes, spec 4.4 table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Scan completed; no Finding met `--fail-on`.
    Clean,
    /// Scan completed; gate threshold met — the normal CI failure.
    GateFailed,
    /// Usage error: bad flags, bad config.
    Usage,
    /// Scan error or partial completion (an Engine failed).
    ScanError,
    /// Authorization denied or missing (SEC-001).
    AuthDenied,
    /// Feed data unavailable or too stale under --offline.
    FeedsStale,
}

impl Exit {
    /// Numeric process exit code.
    pub fn code(self) -> u8 {
        match self {
            Exit::Clean => 0,
            Exit::GateFailed => 1,
            Exit::Usage => 2,
            Exit::ScanError => 3,
            Exit::AuthDenied => 4,
            Exit::FeedsStale => 5,
        }
    }
}

impl From<Exit> for std::process::ExitCode {
    fn from(exit: Exit) -> Self {
        std::process::ExitCode::from(exit.code())
    }
}
