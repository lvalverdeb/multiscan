//! Risk scoring formula and explanations. Pure — no I/O (spec 8).
//!
//! `risk_score = 100 × clamp01(S × E × X × C × A × R)` — a pure function of its
//! inputs (RSK-001): no clock, no RNG, no environment, no hash-order
//! dependence. Every missing input takes a documented default and is recorded
//! in `score_explanation.defaults_applied` (RSK-002).
//!
//! R (reachability) arrived with `T-802` and bumped the formula to version 2;
//! see `docs/scoring-migrations.md`.

use multiscan_core::{
    Confidence, Criticality, DataClassification, ScoreExplanation, ScoreFactors, Severity,
};

/// Version of the scoring formula (RSK-003/RSK-004). Any change to factor
/// derivation or the formula itself bumps this and ships a migration note.
///
/// - `1` — the original five-factor formula (v1.0).
/// - `2` — adds R, module-level reachability (`T-802`, `FR-017`).
pub const FORMULA_VERSION: &str = "2";

/// Exposure signal for factor E. A probe finding is by definition
/// internet-reachable (spec 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposureSignal {
    /// Confirmed reachable from the internet (e.g. any `WebExposure` finding).
    InternetReachable,
    /// No signal — the documented default applies and is recorded (RSK-002).
    Unknown,
}

/// Exploit-likelihood signal for factor X (spec 8 table).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExploitSignal {
    /// Listed in CISA KEV → 1.00.
    Kev,
    /// EPSS probability → banded per spec 8.
    Epss(f64),
    /// The weakness has no CVE (secrets, IaC, exposures) → 0.55.
    NoCve,
    /// Enrichment unavailable (no feed snapshot) → 0.50, recorded as default.
    Unavailable,
}

/// Module-level reachability signal for factor R (`FR-017`, `T-801`).
///
/// **Three states, and the middle one is the point.** `Unknown` must never
/// behave like `NotReferenced`: suppressing a real Finding because the parser
/// did not understand a file is a far worse failure than carrying noise. So
/// `Unknown` is neutral (1.00) while `NotReferenced` lowers the score.
///
/// The claim is deliberately weak. At module granularity `Referenced` means
/// "the package is imported", not "the vulnerable symbol is called" — `NG-2`
/// forbids the latter permanently, and ADR 0013 defers symbol granularity until
/// a symbol-rich ecosystem joins the language set. The weights are calibrated
/// to that weaker claim: they nudge rank, they do not dominate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilitySignal {
    /// Scanned source imports the affected package → raises the score.
    Referenced,
    /// Source parsed successfully and no import was found → lowers the score.
    NotReferenced,
    /// Unsupported language, unparseable file, no package to resolve, or no
    /// source scanned at all → neutral, and recorded as a default (RSK-002).
    Unknown,
}

/// Scoring context from `[risk]` config (spec 4.5); `None` fields take
/// documented defaults and are recorded (RSK-002).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RiskContext {
    /// Factor A base input.
    pub asset_criticality: Option<Criticality>,
    /// Factor A modifier input.
    pub data_classification: Option<DataClassification>,
}

/// Everything the formula consumes for one Finding.
#[derive(Debug, Clone, PartialEq)]
pub struct ScoringInputs {
    /// Derived ordinal severity.
    pub severity: Severity,
    /// CVSS base score 0.0–10.0 when an advisory carries one; S uses
    /// `max(ordinal, cvss_base/10)`.
    pub cvss_base: Option<f64>,
    /// Merged confidence.
    pub confidence: Confidence,
    /// Exposure signal.
    pub exposure: ExposureSignal,
    /// Exploit-likelihood signal.
    pub exploit: ExploitSignal,
    /// Module-level reachability signal (`FR-017`).
    pub reachability: ReachabilitySignal,
    /// Scoring context from config.
    pub context: RiskContext,
    /// FeedSnapshot the enrichment came from (RSK-003).
    pub feed_snapshot_id: Option<String>,
}

/// A computed score plus its full explanation (RSK-005).
#[derive(Debug, Clone, PartialEq)]
pub struct Scored {
    /// 0.0–100.0.
    pub risk_score: f64,
    /// All five factors, the raw product, defaults applied, snapshot id.
    pub explanation: ScoreExplanation,
}

/// Documented ordinal → S mapping (range 0.05–1.00).
fn severity_base(severity: Severity, cvss_base: Option<f64>) -> f64 {
    let ordinal: f64 = match severity {
        Severity::Informational => 0.05,
        Severity::Low => 0.25,
        Severity::Medium => 0.50,
        Severity::High => 0.75,
        Severity::Critical => 1.00,
    };
    match cvss_base {
        Some(cvss) => ordinal.max((cvss / 10.0).clamp(0.0, 1.0)),
        None => ordinal,
    }
}

/// Compute the risk score and its explanation (spec 8).
pub fn score(inputs: &ScoringInputs) -> Scored {
    let mut defaults: Vec<String> = Vec::new();

    let s = severity_base(inputs.severity, inputs.cvss_base);

    // E — exposure, 0.30–1.00. Documented default 0.70 when no signal exists.
    let e = match inputs.exposure {
        ExposureSignal::InternetReachable => 1.00,
        ExposureSignal::Unknown => {
            defaults.push("exposure".into());
            0.70
        }
    };

    // X — exploitability, 0.20–1.00, banded per the spec 8 table.
    let x = match inputs.exploit {
        ExploitSignal::Kev => 1.00,
        ExploitSignal::Epss(p) => {
            if p >= 0.5 {
                0.90
            } else if p >= 0.1 {
                0.70
            } else {
                0.45
            }
        }
        ExploitSignal::NoCve => 0.55,
        ExploitSignal::Unavailable => {
            defaults.push("exploitability".into());
            0.50
        }
    };

    // C — confidence (spec 8 table).
    let c = match inputs.confidence {
        Confidence::Proven => 1.00,
        Confidence::Corroborated => 0.85,
        Confidence::Heuristic => 0.70,
        Confidence::Unconfirmed => 0.50,
    };

    // A — asset criticality, 0.50–1.30. Documented base mapping below;
    // +0.10 for sensitive/regulated data, clamped at 1.30 (spec 8).
    let a_base: f64 = match inputs.context.asset_criticality {
        Some(Criticality::Low) => 0.50,
        Some(Criticality::Medium) => 1.00,
        Some(Criticality::High) => 1.10,
        Some(Criticality::Critical) => 1.20,
        None => {
            defaults.push("asset_criticality".into());
            1.00
        }
    };
    let a = match inputs.context.data_classification {
        Some(DataClassification::Sensitive) | Some(DataClassification::Regulated) => {
            (a_base + 0.10).min(1.30)
        }
        Some(_) => a_base,
        None => a_base,
    };

    // R — module-level reachability, 0.65–1.10 (FR-017, formula_version 2).
    //
    // Unknown is NEUTRAL, not pessimistic: it must not behave like
    // NotReferenced, or an unsupported language would silently suppress real
    // Findings. The spread is deliberately narrow because a module-level
    // import is weak evidence (ADR 0013).
    let r = match inputs.reachability {
        ReachabilitySignal::Referenced => 1.10,
        ReachabilitySignal::NotReferenced => 0.65,
        ReachabilitySignal::Unknown => {
            defaults.push("reachability".into());
            1.00
        }
    };

    let raw_product = s * e * x * c * a * r;
    let risk_score = 100.0 * raw_product.clamp(0.0, 1.0);

    defaults.sort();

    Scored {
        risk_score,
        explanation: ScoreExplanation {
            formula_version: FORMULA_VERSION.to_string(),
            feed_snapshot_id: inputs.feed_snapshot_id.clone(),
            factors: ScoreFactors {
                severity_base: s,
                exposure: e,
                exploitability: x,
                confidence: c,
                asset_criticality: a,
                reachability: r,
            },
            raw_product,
            defaults_applied: defaults,
        },
    }
}
