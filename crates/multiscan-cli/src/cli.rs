//! clap command tree (spec 4.1, 4.2). Parsing only — behaviour lives in the
//! subcommand modules. clap usage errors exit 2 (spec 4.4).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// MultiScan: unified security scanning in a single binary.
#[derive(Parser)]
#[command(name = "multiscan", version, about)]
pub struct Cli {
    /// Subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands (spec 4.1).
#[derive(Subcommand)]
pub enum Command {
    /// Scan a local path (default: .), an OCI image, or an authorized web target
    Scan(Box<ScanArgs>),
    /// Ingest external scanner output via a Bridge
    Import {
        /// Report file to import (SARIF, Trivy JSON, ...)
        file: PathBuf,
        /// Output format: table | json | jsonl | sarif | sbom | markdown
        #[arg(long)]
        format: Option<String>,
    },
    /// Re-render stored Findings in another format
    Report,
    /// Full score breakdown, evidence, remediation for one Finding
    Explain {
        /// Finding id or unique prefix
        finding_id: String,
    },
    /// Delta against a baseline Finding set
    Diff {
        /// Baseline file
        baseline: PathBuf,
    },
    /// Manage suppressions
    Suppress {
        /// add | list | expire
        #[command(subcommand)]
        action: SuppressCmd,
    },
    /// Manage the local feed/finding database
    Db {
        /// update | status | export | import | path
        #[command(subcommand)]
        action: DbCmd,
    },
    /// Manage rule packs
    Rules {
        /// list | validate | pin
        #[command(subcommand)]
        action: RulesCmd,
    },
    /// Manage scope authorizations
    Authorize {
        /// create | verify | show
        #[command(subcommand)]
        action: AuthorizeCmd,
    },
    /// Emit a shell completion script
    Completions {
        /// Target shell
        shell: clap_complete::Shell,
    },
}

/// `multiscan scan` arguments (spec 4.2).
#[derive(Args)]
pub struct ScanArgs {
    /// Remote target kind; omitted = local path scan.
    #[command(subcommand)]
    pub target: Option<ScanTarget>,

    /// Local path to scan.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Layers to run (csv: sca,secrets,iac,sast,probe); default auto-detect.
    #[arg(long, value_delimiter = ',')]
    pub layers: Option<Vec<String>>,

    /// Scan profile: quick | standard | thorough.
    #[arg(long)]
    pub profile: Option<String>,

    /// Output format: table | json | jsonl | sarif | sbom | markdown.
    #[arg(long)]
    pub format: Option<String>,

    /// Gate threshold: a risk score number or a severity name. Exit 1 when met.
    #[arg(long)]
    pub fail_on: Option<String>,

    /// Baseline file: gate only on new Findings.
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Never touch the network; fail loudly on stale feeds (exit 5).
    #[arg(long)]
    pub offline: bool,

    /// Maximum acceptable advisory-data age, e.g. 7d.
    #[arg(long)]
    pub max_feed_age: Option<String>,

    /// Display filter (not a gate): minimum severity shown in human output.
    #[arg(long)]
    pub min_severity: Option<String>,

    /// Config file (default: ./multiscan.toml discovered upward).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// ScopeAuthorization file; required for `scan web` (SEC-001).
    #[arg(long)]
    pub authorization: Option<PathBuf>,

    /// Engine parallelism (default: logical CPUs).
    #[arg(long)]
    pub jobs: Option<usize>,

    /// Disable colored output.
    #[arg(long)]
    pub no_color: bool,

    /// Machine output on stdout only.
    #[arg(long)]
    pub quiet: bool,

    /// Verbose diagnostics on stderr.
    #[arg(long)]
    pub verbose: bool,

    /// Dev-only: register the testkit fixture engine emitting N findings.
    /// Exists for the determinism harness and pipeline tests; not a product
    /// surface and never relaxes authorization (SEC-009 untouched).
    #[arg(long, hide = true)]
    pub testkit_fixture: Option<u64>,

    /// Dev-only: make the testkit fixture end with a Partial outcome.
    #[arg(long, hide = true)]
    pub testkit_partial: bool,

    /// Stateless scan: do not read or write the findings database (STO-003).
    #[arg(long)]
    pub no_store: bool,

    /// Ingest an external scanner report (SARIF/Trivy/Semgrep/Checkov/ZAP) into
    /// the same dedup pass as native findings (BRG-001). Repeatable.
    #[arg(long = "import", value_name = "FILE")]
    pub import: Vec<PathBuf>,
}

/// Remote scan targets.
#[derive(Subcommand)]
pub enum ScanTarget {
    /// Scan an OCI image by reference or digest
    Image {
        /// Image reference, e.g. alpine:3.20 or a digest
        reference: String,
    },
    /// Template-probe an authorized web target
    Web {
        /// Target URL
        url: String,
    },
}

/// Suppression subcommands.
#[derive(Subcommand)]
pub enum SuppressCmd {
    /// Add a suppression (requires justification, approver, expiry — CLI-006)
    Add {
        /// Finding id (or unique prefix) to suppress
        finding_id: String,
        /// Why it is suppressed (mandatory, CLI-006)
        #[arg(long)]
        justification: String,
        /// Who approved it (mandatory, CLI-006)
        #[arg(long)]
        approver: String,
        /// Expiry date, RFC 3339 (mandatory — permanent suppression does not
        /// exist, CLI-006)
        #[arg(long)]
        expires: String,
    },
    /// List active and expired suppressions
    List,
    /// Expire a suppression now
    Expire {
        /// Finding id (or unique prefix) to expire
        finding_id: String,
    },
}

/// Database subcommands.
#[derive(Subcommand)]
pub enum DbCmd {
    /// Fetch feed updates (the ONLY command that fetches feeds, FD-003)
    Update,
    /// Show snapshot ages and digests
    Status,
    /// Export a signed air-gap bundle
    Export,
    /// Import a signed air-gap bundle
    Import,
    /// Print the database path
    Path,
}

/// Rule pack subcommands.
#[derive(Subcommand)]
pub enum RulesCmd {
    /// List bundled and pinned rule packs
    List,
    /// Validate a rule pack
    Validate,
    /// Pin a rule pack version
    Pin,
}

/// Authorization subcommands.
#[derive(Subcommand)]
pub enum AuthorizeCmd {
    /// Create a ScopeAuthorization skeleton
    Create,
    /// Verify signature and validity window
    Verify,
    /// Show an authorization
    Show,
}
