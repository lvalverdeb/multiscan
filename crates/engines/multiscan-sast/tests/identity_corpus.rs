//! `T-703` acceptance: the SAST dedup near-miss corpus.
//!
//! Every merge case is paired with an adversarial near-miss that must **not**
//! merge (CLAUDE.md; spec §16 "dedup adversarial"). False-merge and false-split
//! are tracked separately here because they trade off: loosening the hash to
//! catch a cosmetic edit is exactly what makes two different weaknesses collide.
//!
//! These pairs are **source-level**, which is what makes them useful. The
//! `IdentityKey`-level pairs in `multiscan-dedup/tests/identity.rs` prove the
//! tuple encoding; these prove that real code lowers to the tuple we intended.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use multiscan_sast::lang::{javascript, python};
use multiscan_sast::structural_hash_of;

fn py(src: &str) -> String {
    structural_hash_of(&python::lower_source(src).unwrap())
}

fn js(src: &str) -> String {
    structural_hash_of(&javascript::lower_source(src, false).unwrap())
}

fn ts(src: &str) -> String {
    structural_hash_of(&javascript::lower_source(src, true).unwrap())
}

// ---------------------------------------------------------------------------
// Must merge: the same weakness, cosmetically different.
// ---------------------------------------------------------------------------

#[test]
fn formatting_changes_merge() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "whitespace and blank lines",
            "def f(a):\n    return eval(a)\n",
            "\n\ndef f(a):\n\n        return eval(a)\n\n",
        ),
        (
            "comments are not structure",
            "eval(a)\n",
            "# explain the call\neval(a)  # trailing\n",
        ),
    ];
    for (label, a, b) in cases {
        assert_eq!(py(a), py(b), "should merge: {label}");
    }
}

#[test]
fn moving_code_down_the_file_merges() {
    // Adding statements above a match shifts every span below it. Identity must
    // not notice — this is the single most common cause of baseline churn.
    let plain = python::lower_source("eval(a)\n").unwrap();
    let shifted = python::lower_source("x = 1\ny = 2\nz = 3\neval(a)\n").unwrap();

    assert_eq!(
        structural_hash_of(&plain.children[0]),
        structural_hash_of(shifted.children.last().unwrap()),
    );
}

#[test]
fn literal_values_merge() {
    // ADR 0016 decision 3: raw literal text is excluded from the hash, so
    // rotating a URL, message or magic number does not churn finding_id.
    assert_eq!(py("f(\"a\")\n"), py("f(\"b\")\n"), "string values");
    assert_eq!(py("f(1)\n"), py("f(2)\n"), "number values");
    assert_eq!(py("f(True)\n"), py("f(False)\n"), "bool values");
    assert_eq!(
        py("requests.get(\"http://a.test/v1\")\n"),
        py("requests.get(\"http://b.test/v2\")\n"),
        "a rotated endpoint is the same weakness"
    );
    assert_eq!(js("f(\"a\");\n"), js("f(\"b\");\n"), "js string values");
}

#[test]
fn redundant_syntax_merges() {
    assert_eq!(js("eval(x);\n"), js("eval((x));\n"), "parentheses");
    assert_eq!(
        ts("evil(y);\n"),
        ts("evil(y as any);\n"),
        "typescript assertions are type-level, not structural"
    );
}

// ---------------------------------------------------------------------------
// Must NOT merge: near-misses. One meaningful thing differs.
// ---------------------------------------------------------------------------

#[test]
fn near_misses_do_not_merge() {
    let pairs: &[(&str, &str, &str)] = &[
        ("different argument identifier", "eval(a)\n", "eval(b)\n"),
        ("different callee", "eval(a)\n", "exec(a)\n"),
        ("qualified vs bare call", "os.system(x)\n", "system(x)\n"),
        (
            "different module on the same selector",
            "os.system(x)\n",
            "subprocess.system(x)\n",
        ),
        ("an extra argument", "eval(a)\n", "eval(a, b)\n"),
        ("positional vs keyword argument", "f(x)\n", "f(key=x)\n"),
        (
            "literal kind differs even though values do not count",
            "f(\"a\")\n",
            "f(1)\n",
        ),
        ("different nesting", "eval(a)\n", "def g():\n    eval(a)\n"),
        ("call vs attribute access", "eval(a)\n", "eval.a\n"),
    ];
    for (label, a, b) in pairs {
        assert_ne!(py(a), py(b), "must NOT merge: {label}");
    }
}

#[test]
fn js_near_misses_do_not_merge() {
    let pairs: &[(&str, &str, &str)] = &[
        ("different argument", "eval(a);\n", "eval(b);\n"),
        ("member vs bare", "child_process.exec(c);\n", "exec(c);\n"),
        ("call vs construction", "F(a);\n", "new F(a);\n"),
        ("computed vs static member", "a.b(x);\n", "a[b](x);\n"),
    ];
    for (label, a, b) in pairs {
        assert_ne!(js(a), js(b), "must NOT merge: {label}");
    }
}

// ---------------------------------------------------------------------------
// Documented consequences — surprising but correct.
// ---------------------------------------------------------------------------

#[test]
fn identical_occurrences_in_one_file_share_identity() {
    // Two structurally identical matches in one file produce the SAME identity
    // tuple (rule id, path, structural_hash) and therefore one Finding. Line
    // numbers are deliberately not in identity (§7.7.3) — they change under
    // every edit above them.
    //
    // Consequence worth knowing: fixing one of the two occurrences does not
    // close the Finding. It closes only when the Engine returns Complete and
    // stops reporting it entirely (§7.7.4), i.e. when both are gone.
    let one = python::lower_source("eval(a)\n").unwrap();
    let call = &one.children[0];

    let two = python::lower_source("eval(a)\neval(a)\n").unwrap();
    assert_eq!(two.children.len(), 2);
    assert_eq!(
        structural_hash_of(&two.children[0]),
        structural_hash_of(&two.children[1]),
        "identical occurrences hash identically by design"
    );
    assert_eq!(
        structural_hash_of(call),
        structural_hash_of(&two.children[0])
    );
}

#[test]
fn the_same_construct_hashes_alike_across_languages() {
    // Canonical kinds are language-independent (ADR 0016), so `eval(a)` lowers
    // to the same shape in Python and JavaScript and hashes identically.
    //
    // This can never collide in practice: the identity tuple also carries the
    // normalized path, and one file has one language. Pinned so the property is
    // deliberate rather than a surprise discovered later.
    let p = python::lower_source("eval(a)\n").unwrap();
    let j = javascript::lower_source("eval(a);\n", false).unwrap();
    assert_eq!(
        structural_hash_of(&p.children[0]),
        structural_hash_of(&j.children[0]),
    );
}

#[test]
fn ancestors_do_not_feed_the_hash() {
    // The hash covers the MATCHED SUBTREE, not its context. The same call
    // inside two different functions hashes identically; `pattern-inside`
    // is how a rule distinguishes them, not identity.
    let a = python::lower_source("def handler():\n    eval(x)\n").unwrap();
    let b = python::lower_source("def other():\n    eval(x)\n").unwrap();

    // Function bodies differ in name, so the modules differ...
    assert_ne!(structural_hash_of(&a), structural_hash_of(&b));

    // ...but the matched call subtree inside each is identical.
    let call_a = &a.children[0].children[0].children[0];
    let call_b = &b.children[0].children[0].children[0];
    assert_eq!(structural_hash_of(call_a), structural_hash_of(call_b));
}

// ---------------------------------------------------------------------------
// FR-004: native vs imported.
// ---------------------------------------------------------------------------

#[test]
fn native_and_imported_hashes_are_structurally_disjoint() {
    // The semgrep Bridge synthesizes `semgrep:{blake3(check_id)}` because a
    // JSON report carries no parse tree. Native hashes are `b3:`-prefixed. The
    // two namespaces therefore cannot collide — a native Finding and an
    // imported one for the same upstream rule stay separate.
    //
    // That is a deliberate false-split, not an oversight: merging would need a
    // hash the Bridge cannot compute, and changing the shipped Bridge hash
    // would alter finding_id for published users' baselines. Whether they
    // SHOULD merge is phase-2 Q-11, due before T-705.
    let native = py("eval(a)\n");
    assert!(native.starts_with("b3:"), "native prefix: {native}");

    let imported = format!("semgrep:{}", blake3::hash(b"python.lang.eval").to_hex());
    assert!(imported.starts_with("semgrep:"));
    assert_ne!(native, imported);
}
