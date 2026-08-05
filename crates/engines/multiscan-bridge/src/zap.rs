//! OWASP ZAP JSON importer (spec 7.6). ZAP reports web alerts per site; each
//! alert instance maps to a `WebExposure` keyed by plugin id, origin, and path.

use multiscan_core::{Finding, IdentityKey, Severity};
use serde::Deserialize;

use crate::common::{build, Imported};
use crate::BridgeError;

#[derive(Deserialize)]
struct ZapReport {
    #[serde(default)]
    site: Vec<Site>,
}

#[derive(Deserialize)]
struct Site {
    #[serde(rename = "@name", default)]
    name: String,
    #[serde(default)]
    alerts: Vec<Alert>,
}

#[derive(Deserialize)]
struct Alert {
    #[serde(default)]
    pluginid: String,
    #[serde(default)]
    alert: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    riskcode: Option<String>,
    #[serde(default)]
    desc: Option<String>,
    #[serde(default)]
    instances: Vec<Instance>,
    #[serde(rename = "cweid", default)]
    cwe_id: Option<String>,
}

#[derive(Deserialize)]
struct Instance {
    #[serde(default)]
    uri: String,
}

/// BRG-002: ZAP riskcode → Severity (3 High, 2 Medium, 1 Low, 0 Info).
fn severity(riskcode: Option<&str>) -> Severity {
    match riskcode {
        Some("3") => Severity::High,
        Some("2") => Severity::Medium,
        Some("1") => Severity::Low,
        _ => Severity::Informational,
    }
}

/// Split a URL into (scheme://host:port origin, path).
fn split_origin(url: &str) -> (String, String) {
    // Minimal split; ZAP URIs are absolute. Origin is scheme + authority.
    if let Some(scheme_end) = url.find("://") {
        let after = &url[scheme_end + 3..];
        if let Some(slash) = after.find('/') {
            let origin = format!("{}{}", &url[..scheme_end + 3], &after[..slash]);
            let path = &after[slash..];
            return (origin.to_ascii_lowercase(), path.to_string());
        }
        return (url.to_ascii_lowercase(), "/".to_string());
    }
    (url.to_ascii_lowercase(), "/".to_string())
}

/// Parse a ZAP JSON report into Findings.
pub fn import(bytes: &[u8]) -> Result<Vec<Finding>, BridgeError> {
    let report: ZapReport =
        serde_json::from_slice(bytes).map_err(|e| BridgeError::Parse(e.to_string()))?;
    let mut findings = Vec::new();
    for site in report.site {
        for alert in site.alerts {
            let title = alert
                .alert
                .clone()
                .or_else(|| alert.name.clone())
                .unwrap_or_else(|| format!("ZAP alert {}", alert.pluginid));
            let cwe = alert
                .cwe_id
                .as_ref()
                .filter(|c| !c.is_empty() && *c != "-1")
                .map(|c| vec![format!("CWE-{c}")])
                .unwrap_or_default();
            // One WebExposure per instance URI; fall back to the site name.
            let uris: Vec<String> = if alert.instances.is_empty() {
                vec![site.name.clone()]
            } else {
                alert.instances.iter().map(|i| i.uri.clone()).collect()
            };
            for uri in uris {
                let (origin, path) = split_origin(&uri);
                let identity = IdentityKey::WebExposure {
                    template_id: alert.pluginid.clone(),
                    origin,
                    request_path: path.clone(),
                };
                findings.push(build(Imported {
                    identity,
                    title: title.clone(),
                    description: alert.desc.clone(),
                    severity: severity(alert.riskcode.as_deref()),
                    path,
                    line: None,
                    tool: "zap".to_string(),
                    rule_id: alert.pluginid.clone(),
                    fixed_version: None,
                    cwe: cwe.clone(),
                }));
            }
        }
    }
    Ok(findings)
}
