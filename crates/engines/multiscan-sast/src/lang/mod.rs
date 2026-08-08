//! Language front-ends: real parsers lowered into the common tree (`T-702`).
//!
//! Each front-end owns exactly one job — turning its parser's AST into
//! [`crate::tree::Node`] — and nothing else. Per ADR 0015 decision 5, no
//! `ruff_*` or `swc_*` type appears in a `pub` signature outside its own
//! module, so an upstream AST reshaping is contained here.
//!
//! # One lowering, two uses
//!
//! Leaf pattern text is target-language source with holes (`eval($X)`), so a
//! front-end compiles a pattern by substituting the holes for reserved
//! identifiers, parsing the result with the *same* parser and lowering it with
//! the *same* function as real source, then converting the placeholders back
//! into pattern nodes ([`pattern_from_tree`]).
//!
//! That is what makes `SAST-002` hold by construction rather than by care: a
//! pattern and the source it should match traverse identical code.

use crate::pattern::{PatternNode, SeqItem};
use crate::tree::{Kind, Node};

pub mod javascript;
pub mod python;

/// Reserved identifier prefix a `$NAME` metavariable becomes before parsing.
///
/// Must never be treated as a metavariable in *scanned source* — only pattern
/// text is substituted (`docs/ms-pat-1.md` §3).
pub const METAVAR_PREFIX: &str = "__ms_metavar_";

/// Reserved identifier `...` becomes before parsing. An identifier parses in
/// both expression and statement position in Python and JavaScript, which a
/// bare `...` does not.
pub const ELLIPSIS_IDENT: &str = "__ms_ellipsis";

/// Maximum source size a front-end will parse.
///
/// Scanned source is untrusted; allocation is bounded by input size rather
/// than trusted to be reasonable.
pub const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Rewrite MS-PAT-1 pattern text into something the real parser accepts.
///
/// `$NAME` → `__ms_metavar_NAME`, `...` → `__ms_ellipsis`. Everything else is
/// passed through untouched, so the parser — not us — decides what is valid.
pub fn substitute_placeholders(pattern_text: &str) -> String {
    let mut out = String::with_capacity(pattern_text.len() + 16);
    let bytes: Vec<char> = pattern_text.chars().collect();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == '.' && bytes.get(i + 1) == Some(&'.') && bytes.get(i + 2) == Some(&'.') {
            out.push_str(ELLIPSIS_IDENT);
            i += 3;
            continue;
        }
        if bytes[i] == '$' {
            // `$NAME`: uppercase letters, digits, underscore. `$_` is the
            // anonymous metavariable and becomes `__ms_metavar__`.
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == '_') {
                j += 1;
            }
            if j > i + 1 {
                out.push_str(METAVAR_PREFIX);
                out.extend(&bytes[i + 1..j]);
                i = j;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Wrapper kinds a lone `...` is allowed to stand for.
///
/// Deliberately narrow. These are positional containers the front-end
/// introduces — an `Argument` slot, a statement `Block` — where "`...` here"
/// can only mean "any run of siblings". Every other single-child node is
/// *meaningful*: an `except:` clause whose body is `...` is a handler matching
/// any body, not an ellipsis, and collapsing it would silently turn
/// `try: ... except: ...` into two adjacent ellipses.
const ELLIPSIS_WRAPPERS: &[Kind] = &[Kind::Argument, Kind::Block];

/// True when this node is the lowered form of `...`, seen through the wrapper
/// kinds above only.
fn is_ellipsis_marker(node: &Node) -> bool {
    if node.kind == Kind::Identifier && node.name.as_deref() == Some(ELLIPSIS_IDENT) {
        return true;
    }
    ELLIPSIS_WRAPPERS.contains(&node.kind)
        && node.children.len() == 1
        && is_ellipsis_marker(&node.children[0])
}

/// The metavariable a node denotes, if it is a lowered `$NAME`.
///
/// Returns `Some(None)` for the anonymous `$_`, which binds nothing.
fn metavar_of(node: &Node) -> Option<Option<String>> {
    if node.kind != Kind::Identifier {
        return None;
    }
    let name = node.name.as_deref()?.strip_prefix(METAVAR_PREFIX)?;
    // `$_` substitutes to `__ms_metavar__`, leaving a bare `_`.
    if name == "_" {
        Some(None)
    } else {
        Some(Some(name.to_string()))
    }
}

/// Convert a lowered *pattern* tree into a [`PatternNode`], turning the
/// reserved placeholder identifiers back into metavariables and ellipses.
///
/// Applied only to trees lowered from pattern text — never to scanned source,
/// which is why `__ms_metavar_x` appearing in a real file is just an
/// identifier.
pub fn pattern_from_tree(node: &Node) -> PatternNode {
    if let Some(name) = metavar_of(node) {
        return PatternNode::Metavar { name };
    }

    let children = node
        .children
        .iter()
        .map(|child| {
            if is_ellipsis_marker(child) {
                SeqItem::Ellipsis
            } else {
                SeqItem::Node(pattern_from_tree(child))
            }
        })
        .collect();

    PatternNode::Node {
        kind: node.kind,
        name: node.name.clone(),
        children,
    }
}

/// Unwrap the synthetic module a leaf pattern parses into.
///
/// A leaf pattern is **one construct**, not a file. A multi-statement pattern
/// would otherwise compile to a `Module` pattern that can only ever match at
/// file root — silently never matching anything a rule author meant. Rejection
/// is total, per `docs/ms-pat-1.md` §1.
pub fn single_construct<'a>(
    tree: &'a Node,
    language: &'static str,
) -> Result<&'a Node, LowerError> {
    match tree.children.as_slice() {
        [only] => Ok(only),
        [] => Err(LowerError::Parse {
            language,
            detail: "leaf pattern is empty".to_string(),
        }),
        many => Err(LowerError::Parse {
            language,
            detail: format!(
                "leaf pattern must be a single construct, found {}; \
                 use pattern-inside or separate rules",
                many.len()
            ),
        }),
    }
}

/// Byte offset → 1-based line, for `Location.line`.
///
/// Spans never reach identity (§7.7.3); this exists purely so a Finding can
/// point a human at the right line.
pub struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    /// Build the index for a source file.
    pub fn new(source: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(
            source
                .bytes()
                .enumerate()
                .filter(|(_, b)| *b == b'\n')
                .map(|(i, _)| i + 1),
        );
        LineIndex { starts }
    }

    /// The 1-based line containing `offset`.
    pub fn line(&self, offset: usize) -> u32 {
        match self.starts.binary_search(&offset) {
            Ok(i) => (i + 1) as u32,
            Err(i) => i as u32,
        }
    }
}

/// A front-end failed to parse its input.
#[derive(Debug, thiserror::Error)]
pub enum LowerError {
    /// The source or pattern text did not parse.
    #[error("{language} parse failed: {detail}")]
    Parse {
        /// Which front-end.
        language: &'static str,
        /// Parser-supplied detail.
        detail: String,
    },
    /// Input exceeded [`MAX_SOURCE_BYTES`].
    #[error("source is {size} bytes, exceeding the maximum of {max}")]
    TooLarge {
        /// Observed size.
        size: usize,
        /// The cap.
        max: usize,
    },
    /// The parse exceeded [`PARSE_TIMEOUT`] and was abandoned (Q-12).
    #[error("parse exceeded the {budget:?} budget and was abandoned")]
    Timeout {
        /// The budget that was exceeded.
        budget: std::time::Duration,
    },
    /// Too many parses timed out; this language was abandoned for the scan.
    #[error("skipped: {count} parse timeout(s) already; this language is abandoned for this scan")]
    LanguageAbandoned {
        /// Timeouts observed before giving up.
        count: usize,
    },
}

/// Wall-clock budget for parsing one file.
///
/// Exists because `swc`'s TypeScript grammar backtracks exponentially: a
/// 203-byte file did not finish parsing in ten minutes (Q-12, reproducers in
/// `testdata/corpus/sast-pathological/`). Nothing else bounds it — the input is
/// 203 bytes, so size caps are irrelevant, and `ScanContext`'s deadline and
/// cancel flag are only read *between* files, so control never returns.
///
/// Five seconds is roughly 300× the slowest legitimate *whole-corpus* parse
/// measured for ADR 0015 (554k LOC of Python in 117 ms). No real single file
/// approaches it.
pub const PARSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How many timeouts a language gets before it is abandoned for the scan.
///
/// A timed-out worker cannot be killed — Rust has no such mechanism — so it is
/// abandoned and keeps burning a core until it finishes, which for the
/// pathological input may be never. Without this cap, a repo full of such files
/// would spawn one zombie per file. With it, the damage is bounded at
/// [`MAX_PARSE_TIMEOUTS`] leaked threads per language regardless of repo
/// contents.
pub const MAX_PARSE_TIMEOUTS: usize = 3;

/// Lower source in the given language, unbounded.
///
/// Prefer [`lower_bounded`] for scanned files: this can run arbitrarily long on
/// adversarial input.
pub fn lower(source: &str, language: crate::rules::Language) -> Result<Node, LowerError> {
    match language {
        crate::rules::Language::Python => python::lower_source(source),
        crate::rules::Language::Javascript => javascript::lower_source(source, false),
        crate::rules::Language::Typescript => javascript::lower_source(source, true),
    }
}

/// Tracks parse timeouts across one scan, so the abandoned-thread count stays
/// bounded (see [`MAX_PARSE_TIMEOUTS`]).
///
/// Deliberately not `Sync`: each call site drives its own file loop, and
/// sharing one across threads would make which files get skipped depend on
/// scheduling.
#[derive(Debug, Default)]
pub struct ParseBudget {
    python: usize,
    javascript: usize,
}

impl ParseBudget {
    /// A fresh budget with no timeouts recorded.
    pub fn new() -> Self {
        Self::default()
    }

    fn count(&mut self, language: crate::rules::Language) -> &mut usize {
        match language {
            crate::rules::Language::Python => &mut self.python,
            // TypeScript rides the JavaScript front-end, so they share a fate:
            // the grammar that blows up is the one being abandoned.
            _ => &mut self.javascript,
        }
    }

    /// Whether this language has been abandoned for the rest of the scan.
    pub fn is_abandoned(&mut self, language: crate::rules::Language) -> bool {
        *self.count(language) >= MAX_PARSE_TIMEOUTS
    }

    /// Total timeouts seen, for the degradation reason.
    pub fn timeouts(&self) -> usize {
        self.python + self.javascript
    }
}

/// Lower source with a wall-clock bound, abandoning the parse if it overruns.
///
/// The parse runs on a worker thread and is **abandoned, never killed**, on
/// timeout — Rust cannot kill a thread. The worker keeps running until it
/// finishes; [`MAX_PARSE_TIMEOUTS`] is what stops that from unbounded growth.
///
/// A timed-out file yields no tree, exactly as a parse error does, so the
/// finding set is unaffected either way. The caller must still degrade the
/// scan outcome — a file we failed to read cannot close findings (§7.7.4).
pub fn lower_bounded(
    source: &str,
    language: crate::rules::Language,
    budget: &mut ParseBudget,
) -> Result<Node, LowerError> {
    if budget.is_abandoned(language) {
        return Err(LowerError::LanguageAbandoned {
            count: *budget.count(language),
        });
    }

    // Reject oversize input before spawning: no point paying for a thread to
    // learn what a length check already knows.
    if source.len() > MAX_SOURCE_BYTES {
        return Err(LowerError::TooLarge {
            size: source.len(),
            max: MAX_SOURCE_BYTES,
        });
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let owned = source.to_string();
    // The worker is detached deliberately: on timeout there is nothing to join.
    std::thread::spawn(move || {
        // A closed channel means the caller already gave up; the send fails
        // harmlessly and the thread exits.
        let _ = tx.send(lower(&owned, language));
    });

    match rx.recv_timeout(PARSE_TIMEOUT) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            *budget.count(language) += 1;
            Err(LowerError::Timeout {
                budget: PARSE_TIMEOUT,
            })
        }
        // The worker panicked. Engines must not abort a scan on one bad file.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(LowerError::Parse {
            language: "unknown",
            detail: "parser worker terminated unexpectedly".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution_covers_metavars_and_ellipsis() {
        assert_eq!(substitute_placeholders("eval($X)"), "eval(__ms_metavar_X)");
        assert_eq!(substitute_placeholders("f(...)"), "f(__ms_ellipsis)");
        assert_eq!(
            substitute_placeholders("f(..., $X, ...)"),
            "f(__ms_ellipsis, __ms_metavar_X, __ms_ellipsis)"
        );
        assert_eq!(substitute_placeholders("f($_)"), "f(__ms_metavar__)");
    }

    #[test]
    fn substitution_leaves_ordinary_source_alone() {
        assert_eq!(substitute_placeholders("foo(a, b)"), "foo(a, b)");
        // A lone `$` is not a metavariable and must not be rewritten.
        assert_eq!(substitute_placeholders("cost = $"), "cost = $");
    }

    #[test]
    fn line_index_maps_offsets() {
        let src = "a\nbb\n\nccc";
        let idx = LineIndex::new(src);
        assert_eq!(idx.line(0), 1);
        assert_eq!(idx.line(2), 2);
        assert_eq!(idx.line(6), 4);
    }

    #[test]
    fn ellipsis_marker_is_seen_through_wrappers() {
        let bare = Node::named(Kind::Identifier, ELLIPSIS_IDENT);
        assert!(is_ellipsis_marker(&bare));

        let wrapped = Node::leaf(Kind::Argument).with_children(vec![bare]);
        assert!(is_ellipsis_marker(&wrapped));

        let two_children = Node::leaf(Kind::Argument).with_children(vec![
            Node::named(Kind::Identifier, ELLIPSIS_IDENT),
            Node::named(Kind::Identifier, "x"),
        ]);
        assert!(!is_ellipsis_marker(&two_children));
    }

    #[test]
    fn meaningful_wrappers_do_not_collapse_to_ellipsis() {
        // A handler whose body is `...` matches any body — it is not itself an
        // ellipsis. Collapsing it would turn `try: ... except: ...` into two
        // adjacent ellipses, which the pattern validator rightly rejects.
        let handler = Node::leaf(Kind::Handler).with_children(vec![Node::leaf(Kind::Block)
            .with_children(vec![Node::named(Kind::Identifier, ELLIPSIS_IDENT)])]);
        assert!(!is_ellipsis_marker(&handler));

        // The block inside it, however, does collapse.
        assert!(is_ellipsis_marker(&handler.children[0]));
    }

    #[test]
    fn metavar_conversion_handles_anonymous() {
        let named = Node::named(Kind::Identifier, "__ms_metavar_X");
        assert_eq!(metavar_of(&named), Some(Some("X".to_string())));

        let anon = Node::named(Kind::Identifier, "__ms_metavar__");
        assert_eq!(metavar_of(&anon), Some(None));

        let ordinary = Node::named(Kind::Identifier, "eval");
        assert_eq!(metavar_of(&ordinary), None);
    }
}
