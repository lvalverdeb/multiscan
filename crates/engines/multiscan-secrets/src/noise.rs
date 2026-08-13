//! Known-noise classification for the entropy fallback (ADR 0005, ADR 0021).
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
//!    content-addresses rather than credentials; plus [`source_shaped`]
//!    (ADR 0021), which recognises source identifiers and filesystem paths —
//!    long `snake_case`/`camelCase` names and `/`-joined paths carry enough
//!    symbol variety to clear 4.0 bits without being secrets.

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
    !prefix[scheme_at + 3..].chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '`' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
}

/// Longest all-caps run tolerated inside a segment that came from splitting a
/// `camelCase` run. `SCREAMING_SNAKE` words arrive already delimited and are
/// exempt from the cap; an undelimited run like `AKIAIOSFODNN7EXAMPLE` is the
/// shape of a provider key id, not of a name (ADR 0021).
const MAX_CAPS_RUN: usize = 8;
/// Mean segment length a token must reach to read as words rather than as a
/// random run. Credential alphabets decompose into 1–3 character fragments;
/// identifiers decompose into words.
const MIN_MEAN_SEGMENT: f64 = 3.0;
/// Digits tolerated after a word segment — `s3`, `utf8`, `sha256`, `v2`.
const MAX_TRAILING_DIGITS: usize = 3;
/// Longest pure-number segment still read as a version, index, or year.
const MAX_NUMBER_SEGMENT: usize = 4;
/// Mean component length above which a `/`-joined token stops looking like a
/// filesystem path and starts looking like base64 that happens to contain the
/// separator. Real paths average short components; a credential's slashes are
/// sparse, so its components are long (ADR 0021).
const MAX_PATH_COMPONENT_MEAN: f64 = 10.0;

/// `camelCase` boundaries within one separator-delimited part, yielding
/// borrowed segments without allocating. An uppercase run breaks before a
/// trailing capital that starts a new word, so `SQLAlchemy` yields
/// `SQL`, `Alchemy`.
struct CamelSegments<'a> {
    rest: &'a str,
}

impl<'a> Iterator for CamelSegments<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let bytes = self.rest.as_bytes();
        if bytes.is_empty() {
            return None;
        }
        let mut end = 1;
        if bytes[0].is_ascii_uppercase() {
            while end < bytes.len()
                && bytes[end].is_ascii_uppercase()
                && !bytes.get(end + 1).is_some_and(u8::is_ascii_lowercase)
            {
                end += 1;
            }
            // A lone capital opens a word: absorb its lowercase/digit tail.
            if end == 1 {
                while end < bytes.len()
                    && (bytes[end].is_ascii_lowercase() || bytes[end].is_ascii_digit())
                {
                    end += 1;
                }
            }
        } else {
            while end < bytes.len() && !bytes[end].is_ascii_uppercase() {
                end += 1;
            }
        }
        let (segment, rest) = self.rest.split_at(end);
        self.rest = rest;
        Some(segment)
    }
}

fn camel_segments(part: &str) -> CamelSegments<'_> {
    CamelSegments { rest: part }
}

/// One segment that reads like a word: letters with at most
/// [`MAX_TRAILING_DIGITS`] digits after them, or a short pure number.
/// `cap_caps_run` applies the [`MAX_CAPS_RUN`] limit — set only for parts that
/// actually split at a `camelCase` boundary.
fn word_segment(segment: &str, cap_caps_run: bool) -> bool {
    let bytes = segment.as_bytes();
    let letters = bytes.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    if letters == 0 {
        return bytes.len() <= MAX_NUMBER_SEGMENT && bytes.iter().all(u8::is_ascii_digit);
    }
    let digits = &bytes[letters..];
    if digits.len() > MAX_TRAILING_DIGITS || !digits.iter().all(u8::is_ascii_digit) {
        return false;
    }
    !(cap_caps_run && letters > MAX_CAPS_RUN && bytes[..letters].iter().all(u8::is_ascii_uppercase))
}

/// Whether the token is a source identifier: `snake_case`, `camelCase`,
/// `kebab-case`, `SCREAMING_SNAKE`, or any mixture, including the `/`-joined
/// word chains that appear in prose and test names (ADR 0021).
///
/// Every segment must read as a word, and the segments must average
/// [`MIN_MEAN_SEGMENT`] characters — the property that separates
/// `test_parquet_reader_supports_lazy_dask` from a base62 credential, which
/// shreds into 1–3 character fragments. A token that does not decompose at all
/// is *not* exempt: a solid 20-character run is the shape of a key, not of a
/// name. `+` is not an identifier character in any language we scan but is in
/// the base64 alphabet, so its presence disqualifies the token outright.
pub fn word_shaped(token: &str) -> bool {
    if token.contains('+') {
        return false;
    }
    let mut total = 0usize;
    let mut count = 0usize;
    for part in token.split(['_', '-', '/']) {
        if part.is_empty() {
            continue;
        }
        let split_camel = camel_segments(part).nth(1).is_some();
        for segment in camel_segments(part) {
            if !word_segment(segment, split_camel) {
                return false;
            }
            total += segment.len();
            count += 1;
        }
    }
    count >= 2 && total as f64 / count as f64 >= MIN_MEAN_SEGMENT
}

/// Whether the token is a filesystem path whose every component is innocuous
/// on its own (ADR 0021). The candidate charset includes `/`, so a path like
/// `/var/folders/j1/T/tmp8tivbbt5/events` arrives as one token whose combined
/// symbol variety clears 4.0 bits even though no component would.
///
/// A component that independently trips the detector's own length and entropy
/// bar keeps the whole token in scope — a key inside a path is still a key —
/// and so does a component mean above [`MAX_PATH_COMPONENT_MEAN`], which is
/// what separates a path from a base64 run carrying two or three `/`
/// characters (the documented AWS secret-key shape is exactly that).
pub fn path_shaped(token: &str) -> bool {
    if token.contains('+') || !token.contains('/') {
        return false;
    }
    let components: Vec<&str> = token.split('/').filter(|c| !c.is_empty()).collect();
    if components.len() < 2 {
        return false;
    }
    let total: usize = components.iter().map(|c| c.len()).sum();
    if total as f64 / components.len() as f64 > MAX_PATH_COMPONENT_MEAN {
        return false;
    }
    !components.iter().any(|c| credential_shaped(c))
}

/// A path component that would trip the entropy fallback on its own.
fn credential_shaped(component: &str) -> bool {
    component.len() >= crate::ENTROPY_MIN_LEN
        && !digest_shaped(component)
        && !uuid_shaped(component)
        && !word_shaped(component)
        && crate::shannon_bits(component.as_bytes()) >= crate::ENTROPY_MIN_BITS
}

/// Whether the token is source-shaped — an identifier or a path — and so
/// exempt from the entropy fallback (ADR 0021). Precise provider rules are
/// unaffected: a credential named in an identifier's clothing is still caught
/// by them.
pub fn source_shaped(token: &str) -> bool {
    word_shaped(token) || path_shaped(token)
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

    /// Synthetic credentials in real provider shapes — length, case mixing and
    /// digit scatter matched to the real thing, values invented here. Never
    /// paste a live token into the corpus (SEC-101 in spirit: we do not carry
    /// credentials around, not even other people's expired ones).
    const SYNTHETIC_SECRETS: &[&str] = &[
        "zqR4tL8vNb2xJd6mKp0wYc3sHf9gTa5eUiO", // registry token shape
        "Qm9ndXNLZXlGb3JUZXN0aW5nT25seU5vdA",  // base64 key material
        "hV7kQ2mZ9xWvL3nRtY8bCdE4gJ7sA1uI6oP0wX",
        "R3n9dOmS4lTvAlUeXyZ0",                        // 20-char salt
        "kL4mN8pQ2rS6tU0vW3xY7zA1bC5dE9fG3hJ7kM1n+qR", // base64 with padding alphabet
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",    // documented AWS example shape
        "AKIAIOSFODNN7EXAMPLE",                        // provider key id: undelimited caps run
        "Zx9Qw3Vb7Nk2Rt5Yu8Pm1Lo4Hf6Gd0Sa",
    ];

    #[test]
    fn identifiers_are_word_shaped() {
        for token in [
            "PafActionsTrackerCube",
            "_HybridEngineBoundDataset",
            "test_parquet_reader_supports_lazy_dask_with_explicit_pyarrow_fs",
            "MAGIC_NUMBER_WELL_KNOWN_PORTS",
            "BOTI_EXAMPLE_DIAGNOSTIC_THREADS_PER_WORKER",
            "build_arrow_schema_from_meta_dtypes",
            "SQLAlchemy-compatible",
            "Postgres/MySQL/ClickHouse",
            "check_model_file_load/case_torch_with_weights_only",
            "sha256_digest_of_the_manifest",
        ] {
            assert!(word_shaped(token), "identifier not recognised: {token}");
        }
    }

    #[test]
    fn credential_shapes_are_not_word_shaped() {
        for token in SYNTHETIC_SECRETS {
            assert!(!source_shaped(token), "credential exempted: {token}");
        }
    }

    #[test]
    fn undecomposable_runs_are_not_word_shaped() {
        // A solid run is a key shape, however alphabetic — the exemption needs
        // at least two word segments (ADR 0021).
        assert!(!word_shaped("qhwexrlkjzmnbvcxadfghjkloiuytrew"));
        assert!(!word_shaped("ZXCVBNMASDFGHJKLQWERTYUIOPZXCVBN"));
        // Digits scattered through a segment are not a trailing suffix.
        assert!(!word_shaped(
            "a4c01117d53077e3ac3152503a84e9cf7a5c2395768matplotlib"
        ));
    }

    #[test]
    fn paths_are_exempt_unless_a_component_is_a_credential() {
        assert!(path_shaped(
            "/var/folders/j1/T/boti_sql_manager/warehouse/events"
        ));
        assert!(path_shaped(
            "14/site-packages/mypy/typeshed/stdlib/concurrent/futures/process"
        ));
        // A credential-shaped component keeps the whole token in scope.
        assert!(!path_shaped(
            "/opt/app/config/zqR4tL8vNb2xJd6mKp0wYc3sHf9gTa5eUiO"
        ));
        assert!(!path_shaped(
            "secrets/Qm9ndXNLZXlGb3JUZXN0aW5nT25seU5vdA/current"
        ));
        // So does a component mean no filesystem path would reach: this is the
        // documented AWS secret-key shape, three long base62 runs.
        assert!(!path_shaped("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
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
