//! Module-level import extraction (`T-801`, `FR-017`).
//!
//! Answers exactly one question: **does first-party code reference this module
//! at all?** Not "can tainted input reach it" — `NG-2` forbids that permanently,
//! and ADR 0013 deferred symbol-level reachability until a symbol-rich
//! ecosystem (Go, Rust) joins the language set.
//!
//! The result feeds the reachability risk factor (`T-802`). Because the claim is
//! module-level, it is **weaker evidence than symbol presence**, and
//! `score_explanation` must say *module-level* so a user never reads it as a
//! symbol-level determination (ADR 0013, consequences).
//!
//! # Why this lives here
//!
//! Import extraction needs the parsed tree, so it belongs with the front-ends.
//! ADR 0013 amended `T-801`'s dependency to `T-701` precisely so workstream B
//! would not wait for the full pattern matcher.

use std::collections::BTreeSet;

use crate::rules::Language;
use crate::tree::{Kind, Node};

/// Bare module names imported by a file, in sorted order (`DET-001`).
///
/// Names are as written in source: `os.path` stays `os.path`, `./local` stays
/// relative. Mapping a module name onto a package name is the caller's job —
/// it is ecosystem policy, not a parsing question.
pub type Imports = BTreeSet<String>;

/// Extract every module a lowered file imports.
///
/// Handles the static forms both ecosystems actually use:
///
/// - Python: `import a, b`, `from a.b import c`
/// - JS/TS: `import x from "a"`, `export … from "a"`, and `require("a")`
///
/// Dynamic forms whose argument is not a literal (`__import__(name)`,
/// `require(dynamic)`, `await import(expr)`) are **deliberately not guessed**.
/// A missed import must surface as `Unknown` rather than as `NotReferenced` —
/// suppressing a real Finding because the extractor did not understand a file
/// is far worse than carrying noise (`FR-017`, `RSK-002`).
pub fn extract(tree: &Node, language: Language) -> Imports {
    let mut found = Imports::new();
    walk(tree, language, &mut found);
    found
}

fn walk(node: &Node, language: Language, found: &mut Imports) {
    match node.kind {
        Kind::Import => collect_import(node, found),
        // `require("a")` is a plain call, not an import node.
        Kind::Call if language != Language::Python => collect_require(node, found),
        _ => {}
    }
    for child in &node.children {
        walk(child, language, found);
    }
}

/// An `Import` node's module(s).
///
/// The two front-ends agree on the encoding: when the statement names one
/// module it goes in `name` (`from x import y`, `import x from "y"`); when it
/// names several, each is a child `Identifier` (`import a, b`).
fn collect_import(node: &Node, found: &mut Imports) {
    if let Some(module) = &node.name {
        if !module.is_empty() {
            found.insert(module.clone());
        }
        // `from x import y`: children are symbols, not modules — and
        // symbol-level reachability is deferred (ADR 0013, Q-10).
        return;
    }
    for child in &node.children {
        if child.kind == Kind::Identifier {
            if let Some(module) = &child.name {
                found.insert(module.clone());
            }
        }
    }
}

/// `require("a")` — a call whose callee is `require` and whose sole argument is
/// a string literal.
fn collect_require(node: &Node, found: &mut Imports) {
    let Some((callee, args)) = node.children.split_first() else {
        return;
    };
    if callee.kind != Kind::Identifier || callee.name.as_deref() != Some("require") {
        return;
    }
    let [arg] = args else { return };
    let [literal] = arg.children.as_slice() else {
        return;
    };
    // A non-literal argument is a dynamic require: not guessed, so the factor
    // stays Unknown rather than wrongly reporting NotReferenced.
    if literal.kind == Kind::StringLiteral {
        if let Some(module) = &literal.name {
            found.insert(module.clone());
        }
    }
}

/// Whether an import list references `package`, at module granularity.
///
/// Matches the module itself and any submodule of it (`a.b` and `a/b` both
/// count as referencing `a`), which is what "does this file use the package at
/// all" means in both ecosystems. A scoped npm name (`@scope/pkg`) is compared
/// whole.
pub fn references(imports: &Imports, package: &str) -> bool {
    imports.iter().any(|module| {
        module == package
            || module
                .strip_prefix(package)
                .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('/'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::{javascript, python};

    fn py_imports(src: &str) -> Imports {
        extract(&python::lower_source(src).unwrap(), Language::Python)
    }

    fn js_imports(src: &str) -> Imports {
        extract(
            &javascript::lower_source(src, false).unwrap(),
            Language::Javascript,
        )
    }

    fn set(items: &[&str]) -> Imports {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn python_plain_imports() {
        assert_eq!(py_imports("import os\n"), set(&["os"]));
        assert_eq!(py_imports("import os, sys\n"), set(&["os", "sys"]));
        assert_eq!(py_imports("import os.path\n"), set(&["os.path"]));
    }

    #[test]
    fn python_from_imports_record_the_module_not_the_symbol() {
        // `requests` is the module; `get` is a symbol, and symbol-level
        // reachability is deferred (ADR 0013).
        assert_eq!(py_imports("from requests import get\n"), set(&["requests"]));
        assert_eq!(
            py_imports("from a.b import c, d\n"),
            set(&["a.b"]),
            "submodule path is the module"
        );
    }

    #[test]
    fn python_imports_inside_functions_count() {
        // A deferred import is still a reference.
        assert_eq!(
            py_imports("def f():\n    import yaml\n    return yaml\n"),
            set(&["yaml"])
        );
    }

    #[test]
    fn javascript_static_imports() {
        assert_eq!(js_imports("import fs from 'fs';\n"), set(&["fs"]));
        assert_eq!(
            js_imports("import { a, b } from '@scope/pkg';\n"),
            set(&["@scope/pkg"])
        );
        assert_eq!(
            js_imports("export { x } from 'lodash';\n"),
            set(&["lodash"])
        );
        assert_eq!(js_imports("export * from 'axios';\n"), set(&["axios"]));
    }

    #[test]
    fn javascript_require_counts() {
        assert_eq!(js_imports("const fs = require('fs');\n"), set(&["fs"]));
        assert_eq!(
            js_imports("function f(){ return require('lodash'); }\n"),
            set(&["lodash"])
        );
    }

    #[test]
    fn dynamic_requires_are_not_guessed() {
        // FR-017: a missed import must become Unknown upstream, never
        // NotReferenced. Guessing here would suppress real Findings.
        assert!(js_imports("const m = require(name);\n").is_empty());
        assert!(js_imports("const m = require(a + b);\n").is_empty());
    }

    #[test]
    fn a_file_with_no_imports_yields_nothing() {
        assert!(py_imports("x = 1\n").is_empty());
        assert!(js_imports("const x = 1;\n").is_empty());
    }

    #[test]
    fn references_matches_submodules() {
        let imports = set(&["os.path", "requests", "@scope/pkg/sub"]);
        assert!(references(&imports, "os"), "os.path references os");
        assert!(references(&imports, "os.path"));
        assert!(references(&imports, "requests"));
        assert!(references(&imports, "@scope/pkg"));

        // Prefix-but-not-submodule must not match, or `req` would look like a
        // reference to `requests`.
        assert!(!references(&imports, "req"));
        assert!(!references(&imports, "o"));
        assert!(!references(&imports, "yaml"));
    }

    #[test]
    fn extraction_is_deterministic_and_sorted() {
        let imports = py_imports("import zlib\nimport abc\nimport mmap\n");
        let ordered: Vec<_> = imports.iter().collect();
        assert_eq!(ordered, vec!["abc", "mmap", "zlib"], "sorted (DET-001)");
    }
}
