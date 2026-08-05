//! T-103 acceptance: identity golden vectors, DET-005 normalization, and
//! adversarial near-miss pairs (spec 7.7, 16 "dedup adversarial").

use multiscan_core::IdentityKey;
use multiscan_dedup::{finding_id, normalize_origin, normalize_path};

/// Golden vectors: identity tuple → exact finding_id. Any change to these
/// values invalidates every user's baselines and MUST be treated as a
/// breaking, ADR-worthy event (CLAUDE.md).
#[test]
fn golden_vectors() {
    let raw = include_str!("../../../testdata/vectors/dedup.json");
    let vectors: serde_json::Value = serde_json::from_str(raw).unwrap();
    let cases = vectors["vectors"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let identity: IdentityKey = serde_json::from_value(case["identity"].clone()).unwrap();
        let expected = case["finding_id"].as_str().unwrap();
        let actual = finding_id(&identity);
        assert_eq!(
            actual, expected,
            "finding_id drifted for {:?} — this breaks all baselines",
            identity
        );
    }
}

fn dep_identity(purl: &str, advisory: &str, path: &str) -> IdentityKey {
    IdentityKey::VulnerableDependency {
        purl: purl.into(),
        advisory_id: advisory.into(),
        manifest_path: path.into(),
    }
}

/// DET-005: Windows and POSIX spellings of the same path must not produce
/// different finding_ids.
#[test]
fn path_spellings_converge() {
    let posix = dep_identity("pkg:npm/a@1", "OSV-1", "a/b/package-lock.json");
    for equivalent in [
        r"a\b\package-lock.json",
        "./a/b/package-lock.json",
        "a//b/package-lock.json",
        "/a/b/package-lock.json",
    ] {
        let other = dep_identity("pkg:npm/a@1", "OSV-1", equivalent);
        assert_eq!(
            finding_id(&posix),
            finding_id(&other),
            "spelling {equivalent:?} diverged"
        );
    }
}

#[test]
fn normalize_path_cases() {
    assert_eq!(normalize_path(r"a\b.tf"), "a/b.tf");
    assert_eq!(normalize_path("./x"), "x");
    assert_eq!(normalize_path("././x"), "x");
    assert_eq!(normalize_path("/x/y"), "x/y");
    assert_eq!(normalize_path("x//y"), "x/y");
    assert_eq!(normalize_path("x/y/"), "x/y");
}

#[test]
fn normalize_origin_cases() {
    assert_eq!(
        normalize_origin("HTTPS://Example.com:8443/"),
        "https://example.com:8443"
    );
    assert_eq!(normalize_origin("http://a.example"), "http://a.example");
}

/// Adversarial near-misses: for every merge case there is a pair that must
/// NOT merge (spec 16). One field differs → different finding_id.
#[test]
fn near_misses_do_not_collide() {
    let pairs: Vec<(IdentityKey, IdentityKey)> = vec![
        // Same package+advisory, different lockfile.
        (
            dep_identity("pkg:npm/a@1", "OSV-1", "package-lock.json"),
            dep_identity("pkg:npm/a@1", "OSV-1", "web/package-lock.json"),
        ),
        // Same everything, different advisory.
        (
            dep_identity("pkg:npm/a@1", "OSV-1", "package-lock.json"),
            dep_identity("pkg:npm/a@1", "OSV-2", "package-lock.json"),
        ),
        // Same fields, different class: repo dependency vs container package.
        (
            dep_identity("pkg:npm/a@1", "OSV-1", "x"),
            IdentityKey::ContainerVulnerability {
                purl: "pkg:npm/a@1".into(),
                advisory_id: "OSV-1".into(),
                image_digest: "x".into(),
            },
        ),
        // Same rule+path, different secret fingerprint.
        (
            IdentityKey::ExposedSecret {
                rule_id: "aws-key".into(),
                path: ".env".into(),
                fingerprint: "abcd1234".into(),
            },
            IdentityKey::ExposedSecret {
                rule_id: "aws-key".into(),
                path: ".env".into(),
                fingerprint: "abcd1235".into(),
            },
        ),
        // Same policy+path, different resource address.
        (
            IdentityKey::IacMisconfiguration {
                policy_id: "CIS-2.1".into(),
                path: "main.tf".into(),
                resource_address: "aws_s3_bucket.a".into(),
            },
            IdentityKey::IacMisconfiguration {
                policy_id: "CIS-2.1".into(),
                path: "main.tf".into(),
                resource_address: "aws_s3_bucket.b".into(),
            },
        ),
        // Same template+origin, different matched path.
        (
            IdentityKey::WebExposure {
                template_id: "exposed-env-file".into(),
                origin: "https://staging.example".into(),
                request_path: "/.env".into(),
            },
            IdentityKey::WebExposure {
                template_id: "exposed-env-file".into(),
                origin: "https://staging.example".into(),
                request_path: "/.env.local".into(),
            },
        ),
        // Near-miss on the path itself — normalization must not overreach.
        (
            dep_identity("pkg:npm/a@1", "OSV-1", "a/b.tf"),
            dep_identity("pkg:npm/a@1", "OSV-1", "a/b2.tf"),
        ),
    ];
    for (left, right) in pairs {
        assert_ne!(
            finding_id(&left),
            finding_id(&right),
            "near-miss pair collided: {left:?} vs {right:?}"
        );
    }
}

/// Field-boundary injectivity: shifting a byte across the field boundary must
/// change the id (length-prefixed encoding, not separator-based).
#[test]
fn field_boundaries_are_injective() {
    let a = IdentityKey::ExposedSecret {
        rule_id: "ab".into(),
        path: "c".into(),
        fingerprint: "d".into(),
    };
    let b = IdentityKey::ExposedSecret {
        rule_id: "a".into(),
        path: "bc".into(),
        fingerprint: "d".into(),
    };
    assert_ne!(finding_id(&a), finding_id(&b));
}
