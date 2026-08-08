//! Q-12 acceptance: a pathological file is abandoned, not allowed to hang.
//!
//! The inputs are the real reproducers in `testdata/corpus/sast-pathological/`,
//! found by the `T-704` fuzz soak. Before this bound, `ts-backtrack-4` did not
//! finish parsing in ten minutes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Instant;

use multiscan_sast::lang::{lower_bounded, LowerError, ParseBudget, MAX_PARSE_TIMEOUTS};
use multiscan_sast::rules::Language;

fn reproducer(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/corpus/sast-pathological")
        .join(name);
    std::fs::read_to_string(path).expect("reproducer is committed")
}

#[test]
fn the_unbounded_reproducer_now_terminates() {
    // The whole point: this input previously ran past ten minutes.
    let src = reproducer("ts-backtrack-4-unbounded.ts");
    let mut budget = ParseBudget::new();

    let start = Instant::now();
    let result = lower_bounded(&src, Language::Typescript, &mut budget);
    let elapsed = start.elapsed();

    assert!(
        matches!(result, Err(LowerError::Timeout { .. })),
        "expected a timeout, got {result:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(15),
        "took {elapsed:?} — the bound did not hold"
    );
}

#[test]
fn a_language_is_abandoned_after_repeated_timeouts() {
    // A worker cannot be killed, so each timeout leaks a thread. The cap is
    // what keeps a repo full of pathological files from spawning one per file.
    let src = reproducer("ts-backtrack-4-unbounded.ts");
    let mut budget = ParseBudget::new();

    for i in 0..MAX_PARSE_TIMEOUTS {
        assert!(
            matches!(
                lower_bounded(&src, Language::Typescript, &mut budget),
                Err(LowerError::Timeout { .. })
            ),
            "attempt {i} should time out"
        );
    }
    assert_eq!(budget.timeouts(), MAX_PARSE_TIMEOUTS);

    // Past the cap, further files are skipped without spawning anything.
    let start = Instant::now();
    let result = lower_bounded(&src, Language::Typescript, &mut budget);
    assert!(
        matches!(result, Err(LowerError::LanguageAbandoned { .. })),
        "expected abandonment, got {result:?}"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_millis(100),
        "an abandoned language must short-circuit, not wait out the budget"
    );
}

#[test]
fn abandoning_one_language_does_not_abandon_the_other() {
    // Python is unaffected by a TypeScript grammar blowup and must keep
    // scanning — abandoning it too would be a self-inflicted false negative.
    let src = reproducer("ts-backtrack-4-unbounded.ts");
    let mut budget = ParseBudget::new();
    for _ in 0..MAX_PARSE_TIMEOUTS {
        let _ = lower_bounded(&src, Language::Typescript, &mut budget);
    }
    assert!(budget.is_abandoned(Language::Typescript));

    let tree = lower_bounded("import os\neval(x)\n", Language::Python, &mut budget)
        .expect("python still parses");
    assert!(!tree.children.is_empty());
}

#[test]
fn ordinary_files_never_approach_the_bound() {
    // The budget is ~300x the slowest legitimate whole-corpus parse, so a real
    // file must not come close — otherwise the bound would be a lottery.
    let mut budget = ParseBudget::new();
    let sources = [
        (Language::Python, "def f(a):\n    return eval(a)\n"),
        (
            Language::Javascript,
            "export function f(a){ return eval(a); }\n",
        ),
        (Language::Typescript, "const x: string = evil(y as any);\n"),
    ];
    for (language, src) in sources {
        let start = Instant::now();
        assert!(lower_bounded(src, language, &mut budget).is_ok());
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "{language:?} took {:?} for a trivial file",
            start.elapsed()
        );
    }
    assert_eq!(
        budget.timeouts(),
        0,
        "no legitimate file may consume budget"
    );
}

#[test]
fn the_milder_reproducers_are_bounded_too() {
    // 6.9 s and 20 s under the old code: under the 5 s budget both abandon.
    for name in ["ts-backtrack-1.ts", "ts-backtrack-3.ts"] {
        let src = reproducer(name);
        let mut budget = ParseBudget::new();
        let start = Instant::now();
        let _ = lower_bounded(&src, Language::Typescript, &mut budget);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(15),
            "{name} took {:?}",
            start.elapsed()
        );
    }
}
