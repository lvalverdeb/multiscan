//! Fuzz target for hardened layer extraction (NFR-010, SCA-005).
//!
//! The oracle is NOT "didn't panic" — it is "nothing outside the extraction
//! root changed". We plant a canary beside the root and, after extracting
//! arbitrary attacker-controlled bytes as a layer, assert the canary is
//! untouched and no sibling appeared. cap-std makes escape structurally
//! impossible; this target exists to prove the parser can't be driven into an
//! escape, panic, or unbounded run regardless of input.
//!
//! Run: `cargo +nightly fuzz run tar_extract`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(_) => return,
    };
    let root = dir.path().join("root");
    if std::fs::create_dir(&root).is_err() {
        return;
    }
    let canary = dir.path().join("canary");
    if std::fs::write(&canary, b"canary").is_err() {
        return;
    }

    // Treat the fuzz input as a gzip-compressed layer tarball.
    let _ = multiscan_sca::image::extract_image(&[data.to_vec()], &root);

    // Oracle: the canary and the sibling set are unchanged — no escape.
    assert_eq!(
        std::fs::read(&canary).ok().as_deref(),
        Some(b"canary".as_slice()),
        "extraction escaped the root and modified the canary"
    );
    let siblings = std::fs::read_dir(dir.path())
        .map(|rd| rd.count())
        .unwrap_or(0);
    assert_eq!(siblings, 2, "extraction created a sibling outside the root");
});
