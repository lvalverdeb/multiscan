//! MS-PAT-1 pattern representation: the language-independent operator layer and
//! the compiled leaf-pattern AST (`docs/ms-pat-1.md` §2–§3).
//!
//! # SAST-001 is a property of these types
//!
//! Neither [`PatternExpr`] nor [`PatternNode`] has a variant capable of
//! expressing execution — no eval, no shell-out, no callback, no regex hook.
//! Patterns are data because there is nothing else they *could* be. This is
//! not a check performed at load; it is the shape of the type.
//!
//! # Division of labour with `T-702`
//!
//! This module owns the operator layer and the compiled AST. Turning leaf
//! *pattern text* (`eval($X)` — target-language source with holes) into a
//! [`PatternNode`] requires that language's real parser, so it belongs to the
//! front-ends. The substitution convention they must follow is fixed in
//! `docs/ms-pat-1.md` §3.

use crate::tree::Kind;

/// Maximum nesting depth of a pattern expression or leaf pattern.
///
/// Pattern text arrives from mechanically translated community corpora
/// (ADR 0014) — external data, so recursion is bounded rather than trusted.
pub const MAX_PATTERN_DEPTH: usize = 64;

/// Maximum `...` items in a single child sequence.
///
/// Originally 4, chosen as a proxy bound on the O(n^k) split explosion before
/// anything capped *n*. `MAX_MATCH_STEPS` (`T-704`) now bounds the actual work
/// at match time, and exhausting it degrades the file to `Partial` rather than
/// hanging — so this is a sanity limit, no longer the safety mechanism.
///
/// Raised to 8 on evidence: translating GitLab's MIT-licensed corpus showed
/// real community rules using 5–8 ellipses (Flask path-traversal and
/// open-redirect patterns among them), and at 4 the cap rejected 27 of them at
/// load.
///
/// Measured honestly, this recovered **no additional working rules**: all 27
/// then failed to compile for a different reason (they are multi-statement
/// patterns — see `docs/ms-pat-1.md` §3). The raise stands because the cap was
/// guarding something `MAX_MATCH_STEPS` now guards properly, not because it
/// bought coverage today.
pub const MAX_ELLIPSES_PER_SEQUENCE: usize = 8;

/// An item in a pattern's child sequence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SeqItem {
    /// A pattern that must match exactly one node.
    Node(PatternNode),
    /// `...` — any, possibly empty, run of sibling nodes.
    ///
    /// A sequence operator, never a node: it cannot be bound to a metavariable
    /// and cannot stand as an entire leaf pattern.
    Ellipsis,
}

/// A compiled leaf pattern.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PatternNode {
    /// Match a node of `kind`, whose normalized identifier equals `name` when
    /// `name` is `Some`, and whose children match `children`.
    Node {
        /// Canonical kind that must match.
        kind: Kind,
        /// Required normalized identifier, if the pattern pins one.
        name: Option<String>,
        /// Child sequence, which may contain [`SeqItem::Ellipsis`].
        children: Vec<SeqItem>,
    },
    /// `$NAME` — match exactly one node and bind it.
    ///
    /// `name` is `None` for the anonymous `$_`, which binds nothing and so
    /// imposes no equality constraint when repeated.
    Metavar {
        /// Binding name, or `None` for `$_`.
        name: Option<String>,
    },
}

impl PatternNode {
    /// Reject sequences whose ellipsis use would make matching blow up.
    ///
    /// Two checks, both structural: adjacent `...` is redundant (`..., ...` is
    /// exactly `...`) and doubles the split space for nothing, and more than
    /// [`MAX_ELLIPSES_PER_SEQUENCE`] in one sequence is the O(n^k) case.
    pub fn validate(&self) -> Result<(), PatternError> {
        let PatternNode::Node { children, .. } = self else {
            return Ok(());
        };

        let ellipses = children
            .iter()
            .filter(|item| matches!(item, SeqItem::Ellipsis))
            .count();
        if ellipses > MAX_ELLIPSES_PER_SEQUENCE {
            return Err(PatternError::TooManyEllipses {
                count: ellipses,
                max: MAX_ELLIPSES_PER_SEQUENCE,
            });
        }
        if children
            .windows(2)
            .any(|w| matches!(w, [SeqItem::Ellipsis, SeqItem::Ellipsis]))
        {
            return Err(PatternError::AdjacentEllipses);
        }

        children.iter().try_for_each(|item| match item {
            SeqItem::Node(node) => node.validate(),
            SeqItem::Ellipsis => Ok(()),
        })
    }

    /// Nesting depth of this leaf pattern.
    pub fn depth(&self) -> usize {
        match self {
            PatternNode::Metavar { .. } => 1,
            PatternNode::Node { children, .. } => {
                1 + children
                    .iter()
                    .map(|item| match item {
                        SeqItem::Node(node) => node.depth(),
                        SeqItem::Ellipsis => 1,
                    })
                    .max()
                    .unwrap_or(0)
            }
        }
    }
}

/// An MS-PAT-1 pattern expression: the operator layer.
///
/// The variants are exactly the operators in `docs/ms-pat-1.md` §2. Taint mode
/// is absent permanently (`NG-2`); join mode, autofix, `metavariable-pattern`,
/// `metavariable-comparison` and `pattern-regex` are absent until their own
/// ADR. A pack using any of them is rejected at load — there is no variant to
/// deserialize them into.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PatternExpr {
    /// `pattern` — a single leaf pattern.
    Pattern(PatternNode),
    /// `patterns` — conjunction; every operand must hold at the same node.
    All(Vec<PatternExpr>),
    /// `pattern-either` — disjunction.
    Either(Vec<PatternExpr>),
    /// `pattern-not` — the operand must not match at this node.
    Not(Box<PatternExpr>),
    /// `pattern-inside` — the match must occur beneath a match of the operand.
    Inside(Box<PatternExpr>),
    /// `pattern-not-inside` — the match must not occur beneath a match of the
    /// operand.
    NotInside(Box<PatternExpr>),
}

impl PatternExpr {
    /// Nesting depth of the expression tree, counting into leaf patterns.
    pub fn depth(&self) -> usize {
        match self {
            PatternExpr::Pattern(node) => node.depth(),
            PatternExpr::All(list) | PatternExpr::Either(list) => {
                1 + list.iter().map(PatternExpr::depth).max().unwrap_or(0)
            }
            PatternExpr::Not(inner)
            | PatternExpr::Inside(inner)
            | PatternExpr::NotInside(inner) => 1 + inner.depth(),
        }
    }

    /// Reject structurally invalid expressions before matching ever runs.
    ///
    /// Catches what the type system cannot: over-deep nesting, empty operand
    /// lists, and a bare ellipsis standing as a whole leaf pattern.
    pub fn validate(&self) -> Result<(), PatternError> {
        if self.depth() > MAX_PATTERN_DEPTH {
            return Err(PatternError::TooDeep {
                depth: self.depth(),
                max: MAX_PATTERN_DEPTH,
            });
        }
        self.validate_inner()
    }

    fn validate_inner(&self) -> Result<(), PatternError> {
        match self {
            PatternExpr::Pattern(node) => node.validate(),
            PatternExpr::All(list) | PatternExpr::Either(list) => {
                if list.is_empty() {
                    return Err(PatternError::EmptyOperandList);
                }
                list.iter().try_for_each(PatternExpr::validate_inner)
            }
            PatternExpr::Not(inner)
            | PatternExpr::Inside(inner)
            | PatternExpr::NotInside(inner) => inner.validate_inner(),
        }
    }
}

/// Why a pattern was rejected. Rejection is always at pack load — a rule is
/// never silently downgraded or partially applied (`docs/ms-pat-1.md` §1).
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum PatternError {
    /// Nesting exceeded [`MAX_PATTERN_DEPTH`].
    #[error("pattern nests {depth} deep, exceeding the maximum of {max}")]
    TooDeep {
        /// Observed depth.
        depth: usize,
        /// The cap.
        max: usize,
    },
    /// `patterns` or `pattern-either` with no operands.
    #[error("operator has an empty operand list")]
    EmptyOperandList,
    /// A leaf pattern consisting solely of `...`.
    #[error("`...` is a sequence operator and cannot be an entire pattern")]
    BareEllipsis,
    /// Too many `...` in one child sequence — see [`MAX_ELLIPSES_PER_SEQUENCE`].
    #[error("child sequence has {count} `...` items, exceeding the maximum of {max}")]
    TooManyEllipses {
        /// Observed count.
        count: usize,
        /// The cap.
        max: usize,
    },
    /// `..., ...` — redundant, and it doubles the split space for nothing.
    #[error("adjacent `...` items are redundant; use a single `...`")]
    AdjacentEllipses,
    /// An operator outside MS-PAT-1.
    #[error("`{0}` is not an MS-PAT-1 operator")]
    UnknownOperator(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metavar(name: &str) -> PatternNode {
        PatternNode::Metavar {
            name: Some(name.to_string()),
        }
    }

    /// `eval($X)` compiled — what a front-end produces from pattern text.
    fn eval_of_x() -> PatternNode {
        PatternNode::Node {
            kind: Kind::Call,
            name: None,
            children: vec![
                SeqItem::Node(PatternNode::Node {
                    kind: Kind::Identifier,
                    name: Some("eval".to_string()),
                    children: vec![],
                }),
                SeqItem::Node(PatternNode::Node {
                    kind: Kind::Argument,
                    name: None,
                    children: vec![SeqItem::Node(metavar("X"))],
                }),
            ],
        }
    }

    #[test]
    fn depth_reaches_into_leaf_patterns() {
        assert_eq!(metavar("X").depth(), 1);
        assert_eq!(eval_of_x().depth(), 3);
        assert_eq!(PatternExpr::Pattern(eval_of_x()).depth(), 3);
        assert_eq!(
            PatternExpr::Not(Box::new(PatternExpr::Pattern(eval_of_x()))).depth(),
            4
        );
    }

    #[test]
    fn over_deep_patterns_are_rejected() {
        let mut expr = PatternExpr::Pattern(metavar("X"));
        for _ in 0..MAX_PATTERN_DEPTH {
            expr = PatternExpr::Not(Box::new(expr));
        }
        assert!(matches!(expr.validate(), Err(PatternError::TooDeep { .. })));
    }

    #[test]
    fn empty_operand_lists_are_rejected() {
        assert_eq!(
            PatternExpr::Either(vec![]).validate(),
            Err(PatternError::EmptyOperandList)
        );
        assert_eq!(
            PatternExpr::All(vec![]).validate(),
            Err(PatternError::EmptyOperandList)
        );
        // Nested, not just at the root.
        let nested = PatternExpr::Not(Box::new(PatternExpr::All(vec![])));
        assert_eq!(nested.validate(), Err(PatternError::EmptyOperandList));
    }

    #[test]
    fn adjacent_ellipses_are_rejected() {
        // `..., ...` is exactly `...` and doubles the split space for nothing.
        let expr = PatternExpr::Pattern(PatternNode::Node {
            kind: Kind::Call,
            name: None,
            children: vec![SeqItem::Ellipsis, SeqItem::Ellipsis],
        });
        assert_eq!(expr.validate(), Err(PatternError::AdjacentEllipses));
    }

    #[test]
    fn too_many_ellipses_in_one_sequence_are_rejected() {
        // The O(n^k) case: bounded at load, never at runtime.
        let mut children = Vec::new();
        for _ in 0..=MAX_ELLIPSES_PER_SEQUENCE {
            children.push(SeqItem::Ellipsis);
            children.push(SeqItem::Node(metavar("X")));
        }
        let expr = PatternExpr::Pattern(PatternNode::Node {
            kind: Kind::Call,
            name: None,
            children,
        });
        assert!(matches!(
            expr.validate(),
            Err(PatternError::TooManyEllipses { .. })
        ));
    }

    #[test]
    fn ellipsis_checks_reach_nested_sequences() {
        // The blowup can hide one level down.
        let inner = PatternNode::Node {
            kind: Kind::Argument,
            name: None,
            children: vec![SeqItem::Ellipsis, SeqItem::Ellipsis],
        };
        let expr = PatternExpr::Pattern(PatternNode::Node {
            kind: Kind::Call,
            name: None,
            children: vec![SeqItem::Node(inner)],
        });
        assert_eq!(expr.validate(), Err(PatternError::AdjacentEllipses));
    }

    #[test]
    fn well_formed_patterns_validate() {
        let expr = PatternExpr::All(vec![
            PatternExpr::Pattern(eval_of_x()),
            PatternExpr::Not(Box::new(PatternExpr::Pattern(metavar("Y")))),
        ]);
        assert_eq!(expr.validate(), Ok(()));
    }
}
