//! Merge engine emissions into one deduplicated set (spec 7.7, P-2).
//!
//! Order-independent by construction: inputs are sorted into a canonical order
//! before any first-wins choice is made, so rayon completion order cannot leak
//! into output (DET-002 at the data layer).

use std::collections::BTreeMap;

use multiscan_core::{Confidence, Evidence, RawFinding, Remediation, Severity, Source};

use crate::identity::finding_id;

/// A `RawFinding` paired with the engine that emitted it. The sink records the
/// attribution; engines never self-report it (ENG-003).
#[derive(Debug, Clone, PartialEq)]
pub struct Attributed {
    /// Manifest id of the emitting engine or bridge, e.g. `multiscan.sca`.
    pub engine_id: String,
    /// The emission itself.
    pub raw: RawFinding,
}

/// One deduplicated observation, pre-enrichment and pre-scoring: everything a
/// `Finding` carries except `status`, `risk_score`, and `score_explanation`
/// (those are added by the risk stage).
#[derive(Debug, Clone, PartialEq)]
pub struct MergedFinding {
    /// Stable identity hash (spec 7.7.1).
    pub finding_id: String,
    /// The identity tuple the id was computed from.
    pub identity: multiscan_core::IdentityKey,
    /// Title from the canonically-first source.
    pub title: String,
    /// Description from the canonically-first source that has one.
    pub description: Option<String>,
    /// Maximum severity across sources.
    pub severity: Severity,
    /// Merged confidence; two distinct engines escalate to ≥ Corroborated (7.7.5).
    pub confidence: Confidence,
    /// Asset from the canonically-first source.
    pub asset: multiscan_core::Asset,
    /// Location from the canonically-first source.
    pub location: multiscan_core::Location,
    /// Union of evidence, sorted, exact duplicates removed.
    pub evidence: Vec<Evidence>,
    /// Every (engine_id, rule_id) that reported this Finding, sorted, unique.
    pub sources: Vec<Source>,
    /// Best remediation across sources (fix_available preferred, then detail).
    pub remediation: Option<Remediation>,
    /// Union of CWE ids, sorted, unique.
    pub cwe: Vec<String>,
}

/// Merge attributed emissions into deduplicated findings, sorted by
/// `finding_id`. Same multiset of inputs in any order ⇒ identical output.
pub fn merge(inputs: Vec<Attributed>) -> Vec<MergedFinding> {
    // Group by finding_id. BTreeMap gives deterministic group order (DET-001).
    let mut groups: BTreeMap<String, Vec<Attributed>> = BTreeMap::new();
    for input in inputs {
        let id = finding_id(&input.raw.identity);
        groups.entry(id).or_default().push(input);
    }

    groups
        .into_iter()
        .map(|(id, mut group)| {
            // Canonical in-group order: first-wins choices become input-order
            // independent. Sort key: engine_id, rule_id, title.
            group.sort_by(|a, b| {
                (&a.engine_id, &a.raw.rule_id, &a.raw.title).cmp(&(
                    &b.engine_id,
                    &b.raw.rule_id,
                    &b.raw.title,
                ))
            });
            merge_group(id, group)
        })
        .collect()
}

fn merge_group(finding_id: String, group: Vec<Attributed>) -> MergedFinding {
    let first = &group[0];

    let severity = group
        .iter()
        .map(|a| a.raw.severity)
        .max()
        .unwrap_or(first.raw.severity);

    let mut confidence = group
        .iter()
        .map(|a| a.raw.confidence)
        .max()
        .unwrap_or(first.raw.confidence);
    // 7.7.5: two distinct engine_ids reporting the same finding_id escalate
    // confidence to at least Corroborated.
    let distinct_engines: BTreeMap<&str, ()> =
        group.iter().map(|a| (a.engine_id.as_str(), ())).collect();
    if distinct_engines.len() >= 2 && confidence < Confidence::Corroborated {
        confidence = Confidence::Corroborated;
    }

    let mut evidence: Vec<Evidence> = group.iter().flat_map(|a| a.raw.evidence.clone()).collect();
    evidence.sort_by(|a, b| (&a.kind, &a.summary).cmp(&(&b.kind, &b.summary)));
    evidence.dedup();

    let mut sources: Vec<Source> = group
        .iter()
        .map(|a| Source {
            engine_id: a.engine_id.clone(),
            rule_id: a.raw.rule_id.clone(),
        })
        .collect();
    sources.sort_by(|a, b| (&a.engine_id, &a.rule_id).cmp(&(&b.engine_id, &b.rule_id)));
    sources.dedup();

    // Best remediation: fix_available=true beats false, more detail beats
    // less; ties resolve to the canonically-first source.
    let remediation = group
        .iter()
        .filter_map(|a| a.raw.remediation.as_ref())
        .max_by_key(|r| {
            (
                r.fix_available,
                r.fixed_version.is_some(),
                r.summary.is_some(),
            )
        })
        .cloned();

    let mut cwe: Vec<String> = group.iter().flat_map(|a| a.raw.cwe.clone()).collect();
    cwe.sort();
    cwe.dedup();

    let description = group.iter().find_map(|a| a.raw.description.clone());

    MergedFinding {
        finding_id,
        identity: first.raw.identity.clone(),
        title: first.raw.title.clone(),
        description,
        severity,
        confidence,
        asset: first.raw.asset.clone(),
        location: first.raw.location.clone(),
        evidence,
        sources,
        remediation,
        cwe,
    }
}
