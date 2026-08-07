//! The MS-PAT-1 structural matcher (`docs/ms-pat-1.md` §2–§3).
//!
//! Matching is over the common tree, never over source text — that is what
//! makes `SAST-002` hold: a reformatted file lowers to the same tree, so it
//! produces the same match and the same `finding_id`.
//!
//! Bindings are `BTreeMap`-ordered and every branch is tried in declaration
//! order, so a match is reproducible run to run (`DET-001`).

use std::collections::BTreeMap;

use crate::pattern::{PatternExpr, PatternNode, SeqItem};
use crate::tree::Node;

/// Maximum tree depth the matcher will descend.
///
/// Scanned source is untrusted input; a pathologically nested file must bound
/// recursion rather than overflow the stack.
pub const MAX_MATCH_DEPTH: usize = 512;

/// Metavariable bindings for one match, ordered for determinism.
///
/// Values borrow the matched tree — matching never clones subtrees, so a large
/// file costs no more than the tree itself (`NFR-003`).
pub type Bindings<'a> = BTreeMap<String, &'a Node>;

/// One match of a rule against a tree.
#[derive(Clone, Debug)]
pub struct Match<'a> {
    /// The matched subtree. Its span locates the Finding; its structural parts
    /// feed `structural_hash`.
    pub node: &'a Node,
    /// Metavariable bindings, `$_` excluded (it binds nothing).
    pub bindings: Bindings<'a>,
}

/// Match a compiled leaf pattern against one node.
fn match_node<'a>(
    pattern: &PatternNode,
    node: &'a Node,
    bindings: Bindings<'a>,
) -> Option<Bindings<'a>> {
    match pattern {
        // `$_` matches one node and binds nothing, so repeating it imposes no
        // equality constraint.
        PatternNode::Metavar { name: None } => Some(bindings),

        PatternNode::Metavar { name: Some(name) } => match bindings.get(name) {
            // Consistent binding: a repeated `$X` must bind structurally equal
            // content, so `foo($X, $X)` matches `foo(a, a)` but not `foo(a, b)`.
            Some(bound) => bound.structurally_eq(node).then_some(bindings),
            None => {
                let mut next = bindings;
                next.insert(name.clone(), node);
                Some(next)
            }
        },

        PatternNode::Node {
            kind,
            name,
            children,
        } => {
            if node.kind != *kind {
                return None;
            }
            // A pattern that pins a name requires that exact normalized
            // identifier; a pattern that does not pin one ignores the node's.
            if let Some(want) = name {
                if node.name.as_deref() != Some(want.as_str()) {
                    return None;
                }
            }
            match_seq(children, &node.children, bindings)
        }
    }
}

/// Match a child sequence, where `...` spans any run of siblings.
///
/// Backtracking: on failure the caller's bindings are untouched, because each
/// attempt works on a clone and only a successful branch is returned.
fn match_seq<'a>(
    items: &[SeqItem],
    nodes: &'a [Node],
    bindings: Bindings<'a>,
) -> Option<Bindings<'a>> {
    match items.split_first() {
        // Both exhausted together, or the pattern ran out with nodes left over.
        None => nodes.is_empty().then_some(bindings),

        Some((SeqItem::Ellipsis, rest)) => {
            // `...` is greedy-agnostic: try every split, shortest first, so the
            // choice is deterministic rather than dependent on tree shape.
            for take in 0..=nodes.len() {
                if let Some(next) = match_seq(rest, &nodes[take..], bindings.clone()) {
                    return Some(next);
                }
            }
            None
        }

        Some((SeqItem::Node(pattern), rest)) => {
            let (first, tail) = nodes.split_first()?;
            let next = match_node(pattern, first, bindings)?;
            match_seq(rest, tail, next)
        }
    }
}

/// Evaluate a pattern expression at one node, given its ancestor chain
/// (outermost first).
fn match_expr<'a>(
    expr: &PatternExpr,
    node: &'a Node,
    ancestors: &[&'a Node],
    bindings: Bindings<'a>,
) -> Option<Bindings<'a>> {
    match expr {
        PatternExpr::Pattern(pattern) => match_node(pattern, node, bindings),

        // Conjunction threads bindings, so a metavariable shared between
        // operands must agree across them.
        PatternExpr::All(list) => list
            .iter()
            .try_fold(bindings, |acc, e| match_expr(e, node, ancestors, acc)),

        // First branch in declaration order wins — pack order is the tiebreak,
        // never iteration order (DET-001).
        PatternExpr::Either(list) => list
            .iter()
            .find_map(|e| match_expr(e, node, ancestors, bindings.clone())),

        // Negation is a filter, not a binder: it must not match, and it
        // contributes no bindings.
        PatternExpr::Not(inner) => match_expr(inner, node, ancestors, bindings.clone())
            .is_none()
            .then_some(bindings),

        PatternExpr::Inside(inner) => {
            let chain = ancestor_chain(node, ancestors);
            // Innermost first, so the nearest enclosing context wins.
            (0..chain.len())
                .rev()
                .find_map(|i| match_expr(inner, chain[i], &chain[..i], bindings.clone()))
        }

        PatternExpr::NotInside(inner) => {
            let chain = ancestor_chain(node, ancestors);
            let found = (0..chain.len())
                .rev()
                .any(|i| match_expr(inner, chain[i], &chain[..i], bindings.clone()).is_some());
            (!found).then_some(bindings)
        }
    }
}

/// Ancestors plus the node itself: `pattern-inside` holds when the operand
/// matches at or above the match site (`docs/ms-pat-1.md` §2).
fn ancestor_chain<'a>(node: &'a Node, ancestors: &[&'a Node]) -> Vec<&'a Node> {
    let mut chain = ancestors.to_vec();
    chain.push(node);
    chain
}

/// Walk `root` and invoke `on_match` for every node where `expr` holds.
///
/// Streams into the callback rather than collecting, so an Engine can forward
/// straight to a `FindingSink` without buffering a whole result set
/// (`NFR-003`). Traversal is pre-order, so matches arrive in source order.
///
/// Subtrees deeper than [`MAX_MATCH_DEPTH`] are not descended into; the rest of
/// the tree still matches, which keeps a pathological file a degraded scan
/// rather than a failed one.
pub fn for_each_match<'a, F>(expr: &PatternExpr, root: &'a Node, mut on_match: F)
where
    F: FnMut(Match<'a>),
{
    let mut ancestors = Vec::new();
    walk(expr, root, &mut ancestors, &mut on_match);
}

fn walk<'a, F>(expr: &PatternExpr, node: &'a Node, ancestors: &mut Vec<&'a Node>, on_match: &mut F)
where
    F: FnMut(Match<'a>),
{
    if ancestors.len() >= MAX_MATCH_DEPTH {
        return;
    }
    if let Some(bindings) = match_expr(expr, node, ancestors, Bindings::new()) {
        on_match(Match { node, bindings });
    }
    ancestors.push(node);
    for child in &node.children {
        walk(expr, child, ancestors, on_match);
    }
    ancestors.pop();
}

/// Collect all matches. Convenience for tests and small trees; Engines should
/// prefer [`for_each_match`] so nothing is buffered.
pub fn matches<'a>(expr: &PatternExpr, root: &'a Node) -> Vec<Match<'a>> {
    let mut found = Vec::new();
    for_each_match(expr, root, |m| found.push(m));
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{Kind, Span};

    // --- builders -------------------------------------------------------

    fn ident(name: &str) -> Node {
        Node::named(Kind::Identifier, name)
    }

    fn arg(inner: Node) -> Node {
        Node::leaf(Kind::Argument).with_children(vec![inner])
    }

    /// `callee(args...)` in the common tree.
    fn call(callee: &str, args: Vec<Node>) -> Node {
        let mut children = vec![ident(callee)];
        children.extend(args.into_iter().map(arg));
        Node::leaf(Kind::Call).with_children(children)
    }

    fn p_ident(name: &str) -> PatternNode {
        PatternNode::Node {
            kind: Kind::Identifier,
            name: Some(name.to_string()),
            children: vec![],
        }
    }

    fn p_metavar(name: &str) -> PatternNode {
        PatternNode::Metavar {
            name: Some(name.to_string()),
        }
    }

    fn p_arg(inner: PatternNode) -> SeqItem {
        SeqItem::Node(PatternNode::Node {
            kind: Kind::Argument,
            name: None,
            children: vec![SeqItem::Node(inner)],
        })
    }

    /// `callee(<items>)` as a pattern.
    fn p_call(callee: &str, items: Vec<SeqItem>) -> PatternNode {
        let mut children = vec![SeqItem::Node(p_ident(callee))];
        children.extend(items);
        PatternNode::Node {
            kind: Kind::Call,
            name: None,
            children,
        }
    }

    // --- leaf matching --------------------------------------------------

    #[test]
    fn metavar_binds_the_matched_node() {
        // eval($X) against eval(user_input)
        let tree = call("eval", vec![ident("user_input")]);
        let expr = PatternExpr::Pattern(p_call("eval", vec![p_arg(p_metavar("X"))]));

        let found = matches(&expr, &tree);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].bindings["X"], &ident("user_input"));
    }

    #[test]
    fn repeated_metavar_requires_equal_content() {
        // foo($X, $X) matches foo(a, a) but not foo(a, b) — ms-pat-1 §3.
        let expr = PatternExpr::Pattern(p_call(
            "foo",
            vec![p_arg(p_metavar("X")), p_arg(p_metavar("X"))],
        ));

        let same = call("foo", vec![ident("a"), ident("a")]);
        let differ = call("foo", vec![ident("a"), ident("b")]);

        assert_eq!(matches(&expr, &same).len(), 1);
        assert!(matches(&expr, &differ).is_empty());
    }

    #[test]
    fn anonymous_metavar_imposes_no_equality() {
        // $_ binds nothing, so foo($_, $_) matches foo(a, b).
        let anon = || SeqItem::Node(PatternNode::Metavar { name: None });
        let expr = PatternExpr::Pattern(p_call(
            "foo",
            vec![
                SeqItem::Node(PatternNode::Node {
                    kind: Kind::Argument,
                    name: None,
                    children: vec![anon()],
                }),
                SeqItem::Node(PatternNode::Node {
                    kind: Kind::Argument,
                    name: None,
                    children: vec![anon()],
                }),
            ],
        ));
        let tree = call("foo", vec![ident("a"), ident("b")]);
        let found = matches(&expr, &tree);
        assert_eq!(found.len(), 1);
        assert!(found[0].bindings.is_empty(), "$_ binds nothing");
    }

    #[test]
    fn wrong_callee_does_not_match() {
        let expr = PatternExpr::Pattern(p_call("eval", vec![p_arg(p_metavar("X"))]));
        let tree = call("exec", vec![ident("x")]);
        assert!(matches(&expr, &tree).is_empty());
    }

    // --- ellipsis -------------------------------------------------------

    #[test]
    fn ellipsis_spans_any_argument_run() {
        // foo(...) matches zero, one, or many arguments.
        let expr = PatternExpr::Pattern(p_call("foo", vec![SeqItem::Ellipsis]));
        for args in [
            vec![],
            vec![ident("a")],
            vec![ident("a"), ident("b"), ident("c")],
        ] {
            let tree = call("foo", args);
            assert_eq!(matches(&expr, &tree).len(), 1);
        }
    }

    #[test]
    fn ellipsis_around_a_pinned_argument() {
        // foo(..., $X, ...) finds a match wherever the argument sits.
        let expr = PatternExpr::Pattern(p_call(
            "foo",
            vec![SeqItem::Ellipsis, p_arg(p_metavar("X")), SeqItem::Ellipsis],
        ));
        let tree = call("foo", vec![ident("a"), ident("b"), ident("c")]);
        let found = matches(&expr, &tree);
        assert_eq!(found.len(), 1);
        // Shortest-split-first makes the binding deterministic: the first
        // argument, not an arbitrary one.
        assert_eq!(found[0].bindings["X"], &ident("a"));
    }

    // --- operator layer -------------------------------------------------

    #[test]
    fn either_takes_the_first_matching_branch() {
        let expr = PatternExpr::Either(vec![
            PatternExpr::Pattern(p_call("exec", vec![SeqItem::Ellipsis])),
            PatternExpr::Pattern(p_call("eval", vec![SeqItem::Ellipsis])),
        ]);
        assert_eq!(matches(&expr, &call("eval", vec![])).len(), 1);
        assert_eq!(matches(&expr, &call("exec", vec![])).len(), 1);
        assert!(matches(&expr, &call("print", vec![])).is_empty());
    }

    #[test]
    fn not_excludes_a_shape() {
        // A call that is not eval(...).
        let expr = PatternExpr::All(vec![
            PatternExpr::Pattern(PatternNode::Node {
                kind: Kind::Call,
                name: None,
                children: vec![SeqItem::Ellipsis],
            }),
            PatternExpr::Not(Box::new(PatternExpr::Pattern(p_call(
                "eval",
                vec![SeqItem::Ellipsis],
            )))),
        ]);
        assert!(matches(&expr, &call("eval", vec![ident("a")])).is_empty());
        assert_eq!(matches(&expr, &call("print", vec![ident("a")])).len(), 1);
    }

    #[test]
    fn all_threads_bindings_across_operands() {
        // Both operands mention $X, so they must agree.
        let expr = PatternExpr::All(vec![
            PatternExpr::Pattern(p_call("foo", vec![p_arg(p_metavar("X"))])),
            PatternExpr::Pattern(p_call("foo", vec![p_arg(p_ident("a"))])),
        ]);
        assert_eq!(matches(&expr, &call("foo", vec![ident("a")])).len(), 1);
        assert!(matches(&expr, &call("foo", vec![ident("b")])).is_empty());
    }

    #[test]
    fn inside_requires_an_enclosing_context() {
        // eval($X) inside a function definition.
        let expr = PatternExpr::All(vec![
            PatternExpr::Pattern(p_call("eval", vec![p_arg(p_metavar("X"))])),
            PatternExpr::Inside(Box::new(PatternExpr::Pattern(PatternNode::Node {
                kind: Kind::Function,
                name: Some("handler".to_string()),
                children: vec![SeqItem::Ellipsis],
            }))),
        ]);

        let inside = Node::named(Kind::Function, "handler")
            .with_children(vec![call("eval", vec![ident("x")])]);
        let outside = Node::named(Kind::Function, "other")
            .with_children(vec![call("eval", vec![ident("x")])]);

        assert_eq!(matches(&expr, &inside).len(), 1);
        assert!(matches(&expr, &outside).is_empty());
    }

    #[test]
    fn not_inside_excludes_an_enclosing_context() {
        let expr = PatternExpr::All(vec![
            PatternExpr::Pattern(p_call("eval", vec![SeqItem::Ellipsis])),
            PatternExpr::NotInside(Box::new(PatternExpr::Pattern(PatternNode::Node {
                kind: Kind::Try,
                name: None,
                children: vec![SeqItem::Ellipsis],
            }))),
        ]);

        let guarded = Node::leaf(Kind::Try).with_children(vec![call("eval", vec![])]);
        let bare = Node::leaf(Kind::Block).with_children(vec![call("eval", vec![])]);

        assert!(matches(&expr, &guarded).is_empty());
        assert_eq!(matches(&expr, &bare).len(), 1);
    }

    // --- traversal and invariants ---------------------------------------

    #[test]
    fn every_occurrence_matches_in_source_order() {
        let tree = Node::leaf(Kind::Block).with_children(vec![
            call("eval", vec![ident("first")]),
            call("print", vec![ident("skip")]),
            call("eval", vec![ident("second")]),
        ]);
        let expr = PatternExpr::Pattern(p_call("eval", vec![p_arg(p_metavar("X"))]));

        let found = matches(&expr, &tree);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].bindings["X"], &ident("first"));
        assert_eq!(found[1].bindings["X"], &ident("second"));
    }

    #[test]
    fn spans_do_not_affect_matching() {
        // SAST-002 at the matcher level: reformatting moves spans and nothing
        // else. The full source-level version arrives with T-702's parsers.
        let expr = PatternExpr::Pattern(p_call("eval", vec![p_arg(p_metavar("X"))]));

        let mut moved = call("eval", vec![ident("x")]);
        moved.span = Span {
            start: 4096,
            end: 4110,
            line: 77,
        };
        moved.children[0].span = Span {
            start: 4096,
            end: 4100,
            line: 77,
        };

        let original = call("eval", vec![ident("x")]);
        let plain = matches(&expr, &original);
        let shifted = matches(&expr, &moved);
        assert_eq!(plain.len(), shifted.len());
        assert_eq!(
            plain[0].node.structural_parts(),
            shifted[0].node.structural_parts()
        );
    }

    #[test]
    fn first_solution_semantics_are_deliberate() {
        // ms-pat-1 §3: matching finds the FIRST solution and does not revisit
        // earlier choice points. Pattern children are `foo(..., $X, ...)` then
        // a sibling `$X`; the tree is `foo(a, b)` then `b`.
        //
        // The ellipsis binds $X=a (shortest split first), the sibling $X then
        // fails against `b`, and the split that would have worked ($X=b) is
        // never tried. Semgrep would find it. This test pins that divergence so
        // it stays a documented property rather than becoming an accident.
        let tree = Node::leaf(Kind::Block)
            .with_children(vec![call("foo", vec![ident("a"), ident("b")]), ident("b")]);
        let expr = PatternExpr::Pattern(PatternNode::Node {
            kind: Kind::Block,
            name: None,
            children: vec![
                SeqItem::Node(p_call(
                    "foo",
                    vec![SeqItem::Ellipsis, p_arg(p_metavar("X")), SeqItem::Ellipsis],
                )),
                SeqItem::Node(p_metavar("X")),
            ],
        });

        assert!(
            matches(&expr, &tree).is_empty(),
            "first-solution matching gives up rather than re-splitting (ms-pat-1 §3)"
        );

        // The same pattern against `foo(b, ...)` succeeds, confirming the
        // failure above is the split choice and not a broken pattern.
        let agreeable = Node::leaf(Kind::Block)
            .with_children(vec![call("foo", vec![ident("b"), ident("c")]), ident("b")]);
        assert_eq!(matches(&expr, &agreeable).len(), 1);
    }

    #[test]
    fn matching_is_reproducible() {
        // DET-001: same inputs, same bindings, every run.
        let tree = call("foo", vec![ident("a"), ident("b"), ident("c")]);
        let expr = PatternExpr::Pattern(p_call(
            "foo",
            vec![SeqItem::Ellipsis, p_arg(p_metavar("X")), SeqItem::Ellipsis],
        ));
        let first = matches(&expr, &tree);
        for _ in 0..50 {
            let again = matches(&expr, &tree);
            assert_eq!(first.len(), again.len());
            assert_eq!(first[0].bindings["X"], again[0].bindings["X"]);
        }
    }

    #[test]
    fn deep_trees_are_bounded_not_fatal() {
        // Untrusted source: a pathological nest degrades, never overflows.
        let mut deep = Node::leaf(Kind::Block);
        for _ in 0..(MAX_MATCH_DEPTH + 50) {
            deep = Node::leaf(Kind::Block).with_children(vec![deep]);
        }
        let expr = PatternExpr::Pattern(PatternNode::Node {
            kind: Kind::Block,
            name: None,
            children: vec![SeqItem::Ellipsis],
        });
        // Terminates, and still reports the part of the tree it did reach.
        assert!(!matches(&expr, &deep).is_empty());
    }
}
