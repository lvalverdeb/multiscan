//! Known-noise classification for the entropy fallback (ADR 0005).
//!
//! Two layers of defence against entropy false positives, both scoped to the
//! heuristic fallback only — precise provider rules always run everywhere:
//!
//! 1. **Path-level** ([`entropy_noise_path`]): file classes that are entropy
//!    noise by construction — lockfiles (content-address hashes), IDE
//!    metadata, minified/bundled assets. Extensible via
//!    `[scan.secrets] entropy_exclude`.
//! 2. **Token-level** ([`digest_shaped`], [`uuid_shaped`],
//!    [`in_url_context`]): strings whose shape identifies them as
//!    content-addresses rather than credentials.

/// Lockfiles: machine-written dependency manifests whose hashes are public
/// checksums. A real credential pasted into one is still caught by the
/// precise provider rules.
const NOISE_BASENAMES: &[&str] = &[
    "uv.lock",
    "Cargo.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
    "packages.lock.json",
    "flake.lock",
    "mix.lock",
];

/// Directories that hold IDE/editor state, not source.
const NOISE_DIR_SEGMENTS: &[&str] = &[".idea", ".vscode"];

/// Generated-asset suffixes: minified bundles and source maps.
const NOISE_SUFFIXES: &[&str] = &[".min.js", ".min.css", ".map"];

/// Whether the entropy fallback is silenced for this root-relative POSIX
/// path by the built-in known-noise list (ADR 0005).
pub fn entropy_noise_path(rel_path: &str) -> bool {
    let basename = rel_path.rsplit('/').next().unwrap_or(rel_path);
    NOISE_BASENAMES.contains(&basename)
        || NOISE_SUFFIXES.iter().any(|s| basename.ends_with(s))
        || rel_path
            .split('/')
            .any(|segment| NOISE_DIR_SEGMENTS.contains(&segment))
}

/// Pure-hex token at a standard digest length: md5 (32), sha1/git (40),
/// sha224 (56), sha256 (64), sha384 (96), sha512/blake2b (128). Hex tops out
/// at 4.0 bits/symbol — exactly the entropy threshold — so digests are the
/// dominant entropy false positive. A hex-encoded *credential* at one of
/// these lengths is indistinguishable by shape; that trade-off is accepted
/// and documented (ADR 0005).
pub fn digest_shaped(token: &str) -> bool {
    matches!(token.len(), 32 | 40 | 56 | 64 | 96 | 128)
        && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// RFC 4122 UUID shape: 8-4-4-4-12 hex groups. The `-` is in the candidate
/// charset, so a UUID arrives as one 36-char token.
pub fn uuid_shaped(token: &str) -> bool {
    if token.len() != 36 {
        return false;
    }
    let parts: Vec<&str> = token.split('-').collect();
    parts.len() == 5
        && [8usize, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(len, part)| part.len() == *len && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Whether the token starting at `token_start` sits inside a URL: a `://`
/// appears earlier in the line with no URL-terminating delimiter between it
/// and the token. Content-address URLs (package registries, artifact stores)
/// are the second-dominant entropy false positive; the candidate charset
/// includes `/`, so an entire URL path arrives as one token. Note the
/// trade-off: a secret embedded in a URL query string is exempted too —
/// provider-shaped ones are still caught by the precise rules (ADR 0005).
pub fn in_url_context(line: &str, token_start: usize) -> bool {
    let prefix = &line[..token_start];
    let Some(scheme_at) = prefix.rfind("://") else {
        return false;
    };
    // Any of these between the scheme and the token means the URL ended.
    !prefix[scheme_at + 3..]
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockfiles_ide_and_minified_are_noise_paths() {
        assert!(entropy_noise_path("uv.lock"));
        assert!(entropy_noise_path("sub/dir/Cargo.lock"));
        assert!(entropy_noise_path(".idea/workspace.xml"));
        assert!(entropy_noise_path("app/.vscode/settings.json"));
        assert!(entropy_noise_path("dist/bundle.min.js"));
        assert!(entropy_noise_path("dist/app.js.map"));
        // Source files are not noise.
        assert!(!entropy_noise_path("src/config.py"));
        assert!(!entropy_noise_path("locker.py"));
        // Only exact basenames match, not substrings.
        assert!(!entropy_noise_path("not-a-uv.lock.md"));
    }

    #[test]
    fn digest_shapes() {
        assert!(digest_shaped("d41d8cd98f00b204e9800998ecf8427e")); // md5
        assert!(digest_shaped("da39a3ee5e6b4b0d3255bfef95601890afd80709")); // sha1
        assert!(digest_shaped(
            "c64d871ed5491a6571948dd48eabd185b46c6c23b64e3afd0c059fc7593ada30"
        )); // sha256
        assert!(!digest_shaped("d41d8cd98f00b204e9800998ecf8427")); // 31 chars
        assert!(!digest_shaped("Zx9Qw3Vb7Nk2Rt5Yu8Pm1Lo4Hf6Gd0Sa")); // 32 but not hex
    }

    #[test]
    fn uuid_shape() {
        assert!(uuid_shaped("48ca8a53-f08e-4065-aebf-02c8604e3185"));
        assert!(!uuid_shaped("48ca8a53-f08e-4065-aebf-02c8604e318")); // short
        assert!(!uuid_shaped("48ca8a53f08e4065aebf02c8604e31850000")); // no dashes
    }

    #[test]
    fn url_context() {
        let line = r#"sdist = { url = "https://files.pythonhosted.org/packages/e7/75/aiobotocore.tar.gz" }"#;
        let start = line.find("/packages").unwrap();
        assert!(in_url_context(line, start));

        // The same shape outside a URL is not exempt.
        let bare = "value = /packages/e7/75/aiobotocore";
        assert!(!in_url_context(bare, bare.find("/packages").unwrap()));

        // A quote after the URL ends its reach.
        let after = r#"x = "https://example.com/a" secret = wJalrXUtnFEMIK7MDENGbPxRfiCY"#;
        assert!(!in_url_context(after, after.find("wJalr").unwrap()));
    }
}
