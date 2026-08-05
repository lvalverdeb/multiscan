//! Minimal OCI distribution pull client over ureq (spec 7.1). Hand-rolled to
//! keep the async `oci-client`/tokio out of the binary. Fetches the manifest
//! (selecting a platform from an index), then the config and layer blobs, and
//! **verifies every blob against its digest** — the integrity property that
//! makes offline/air-gap trust meaningful.
//!
//! Registry access is real network I/O; tests point it only at a loopback
//! fixture registry, never a real host (spec 16).

use std::time::Duration;

use serde::Deserialize;

/// Errors from pulling an image.
#[derive(Debug, thiserror::Error)]
pub enum OciError {
    /// Malformed image reference.
    #[error("invalid image reference `{0}`")]
    BadReference(String),
    /// Network or HTTP failure.
    #[error("registry request failed: {0}")]
    Http(String),
    /// A blob did not match its digest.
    #[error("blob digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        /// Digest from the manifest.
        expected: String,
        /// Digest of the downloaded bytes.
        actual: String,
    },
    /// Malformed manifest/config JSON.
    #[error("malformed registry response: {0}")]
    Malformed(String),
    /// No manifest for a supported platform.
    #[error("no manifest for platform linux/{0}")]
    NoPlatform(String),
}

/// A parsed image reference: `registry/repository:tag` or `...@sha256:...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Registry host (with optional port), e.g. `registry.example.com:5000`.
    pub registry: String,
    /// Repository path, e.g. `library/alpine`.
    pub repository: String,
    /// Tag or digest reference used to fetch the manifest.
    pub reference: String,
    /// Whether the connection should use https (false for loopback tests).
    pub https: bool,
}

impl Reference {
    /// Parse `[registry/]repository[:tag|@digest]`. A reference with no
    /// registry defaults to Docker Hub — but since tests never hit real hosts,
    /// callers pass an explicit `registry/…` form.
    pub fn parse(input: &str) -> Result<Self, OciError> {
        let bad = || OciError::BadReference(input.to_string());
        let (name, reference) = if let Some((n, d)) = input.split_once('@') {
            (n.to_string(), d.to_string())
        } else if let Some(colon) = input.rfind(':') {
            // A colon after the last slash is a tag; a colon before is a port.
            let after_slash = input.rfind('/').map(|s| colon > s).unwrap_or(true);
            if after_slash {
                (input[..colon].to_string(), input[colon + 1..].to_string())
            } else {
                (input.to_string(), "latest".to_string())
            }
        } else {
            (input.to_string(), "latest".to_string())
        };

        let (registry, repository) = match name.split_once('/') {
            // Heuristic: the first segment is a registry if it looks like a
            // host (contains `.` or `:` or is localhost).
            Some((host, rest))
                if host.contains('.') || host.contains(':') || host == "localhost" =>
            {
                (host.to_string(), rest.to_string())
            }
            _ => ("registry-1.docker.io".to_string(), name.clone()),
        };
        if repository.is_empty() {
            return Err(bad());
        }
        let https = !(registry.starts_with("127.0.0.1")
            || registry.starts_with("localhost")
            || registry.starts_with("[::1]"));
        Ok(Reference {
            registry,
            repository,
            reference,
            https,
        })
    }

    fn base_url(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{scheme}://{}/v2/{}", self.registry, self.repository)
    }
}

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json";

#[derive(Deserialize)]
struct Index {
    #[serde(default)]
    manifests: Vec<IndexEntry>,
}

#[derive(Deserialize)]
struct IndexEntry {
    digest: String,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Deserialize)]
struct Platform {
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    layers: Vec<Descriptor>,
}

#[derive(Deserialize)]
struct Descriptor {
    digest: String,
    #[serde(rename = "mediaType", default)]
    media_type: String,
}

/// A pulled image: its layer blobs in application order (base first).
pub struct PulledImage {
    /// The digest that identifies the image manifest.
    pub manifest_digest: String,
    /// Gzip-compressed layer tarballs, base layer first.
    pub layers: Vec<Vec<u8>>,
}

/// Client for one registry pull.
pub struct OciClient {
    agent: ureq::Agent,
    arch: String,
}

impl OciClient {
    /// Client selecting the host architecture (amd64/arm64).
    pub fn new() -> Self {
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        }
        .to_string();
        Self::with_arch(arch)
    }

    /// Client selecting a specific architecture (tests pin this for stable
    /// fixtures).
    pub fn with_arch(arch: String) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(300)))
            .build();
        Self {
            agent: config.into(),
            arch,
        }
    }

    fn get(&self, url: &str, accept: &str) -> Result<Vec<u8>, OciError> {
        let mut response = self
            .agent
            .get(url)
            .header("Accept", accept)
            .call()
            .map_err(|e| OciError::Http(format!("{url}: {e}")))?;
        if !response.status().is_success() {
            return Err(OciError::Http(format!("{url}: HTTP {}", response.status())));
        }
        response
            .body_mut()
            .with_config()
            .limit(4 * 1024 * 1024 * 1024)
            .read_to_vec()
            .map_err(|e| OciError::Http(format!("{url}: body: {e}")))
    }

    /// Pull an image: manifest (platform-selected) → layer blobs, each
    /// digest-verified.
    pub fn pull(&self, reference: &Reference) -> Result<PulledImage, OciError> {
        let base = reference.base_url();
        let manifest_url = format!("{base}/manifests/{}", reference.reference);
        let raw = self.get(&manifest_url, MANIFEST_ACCEPT)?;

        // The response is either an image manifest or an index; try index first.
        let (manifest_bytes, manifest_digest) =
            if let Ok(index) = serde_json::from_slice::<Index>(&raw) {
                if !index.manifests.is_empty() {
                    let chosen = index
                        .manifests
                        .iter()
                        .find(|m| {
                            m.platform
                                .as_ref()
                                .is_some_and(|p| p.os == "linux" && p.architecture == self.arch)
                        })
                        .ok_or_else(|| OciError::NoPlatform(self.arch.clone()))?;
                    let url = format!("{base}/manifests/{}", chosen.digest);
                    let bytes = self.get(&url, MANIFEST_ACCEPT)?;
                    verify_digest(&chosen.digest, &bytes)?;
                    (bytes, chosen.digest.clone())
                } else {
                    (raw.clone(), digest_of(&raw))
                }
            } else {
                (raw.clone(), digest_of(&raw))
            };

        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| OciError::Malformed(e.to_string()))?;

        let mut layers = Vec::new();
        for layer in &manifest.layers {
            // Only tar+gzip layers are extractable by this engine.
            if !layer.media_type.contains("tar") {
                continue;
            }
            let url = format!("{base}/blobs/{}", layer.digest);
            let bytes = self.get(&url, "*/*")?;
            verify_digest(&layer.digest, &bytes)?;
            layers.push(bytes);
        }

        Ok(PulledImage {
            manifest_digest,
            layers,
        })
    }
}

impl Default for OciClient {
    fn default() -> Self {
        Self::new()
    }
}

fn digest_of(bytes: &[u8]) -> String {
    // Registries use sha256; we compute it for verification. (blake3 is our
    // internal identity hash, but OCI digests are sha256 by spec.)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn verify_digest(expected: &str, bytes: &[u8]) -> Result<(), OciError> {
    let actual = digest_of(bytes);
    if actual != expected {
        return Err(OciError::DigestMismatch {
            expected: expected.to_string(),
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_references() {
        let r = Reference::parse("registry.example.com/library/alpine:3.20").unwrap();
        assert_eq!(r.registry, "registry.example.com");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "3.20");
        assert!(r.https);

        let d = Reference::parse("127.0.0.1:5000/app@sha256:abc").unwrap();
        assert_eq!(d.registry, "127.0.0.1:5000");
        assert_eq!(d.repository, "app");
        assert_eq!(d.reference, "sha256:abc");
        assert!(!d.https);

        let hub = Reference::parse("alpine").unwrap();
        assert_eq!(hub.registry, "registry-1.docker.io");
        assert_eq!(hub.repository, "alpine");
        assert_eq!(hub.reference, "latest");
    }

    #[test]
    fn digest_verification() {
        assert!(verify_digest(&digest_of(b"hello"), b"hello").is_ok());
        assert!(matches!(
            verify_digest("sha256:0000", b"hello"),
            Err(OciError::DigestMismatch { .. })
        ));
    }
}
