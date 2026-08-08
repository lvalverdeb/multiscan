//! The common syntax tree both language front-ends lower into (ADR 0015
//! decision 5), and the canonical node-kind vocabulary that feeds
//! [`structural_hash`](crate::structural_hash).
//!
//! Front-ends (`T-702`) translate `ruff`/`swc` ASTs into this shape. No
//! `ruff_*` or `swc_*` type appears here or in any `pub` signature outside its
//! own front-end module, so a parser upgrade — or replacing a parser outright —
//! cannot reach `finding_id`.
//!
//! See `docs/ms-pat-1.md` §4.

use std::fmt;

/// Canonical node kinds: MultiScan's own vocabulary, deliberately **not** the
/// parsers'.
///
/// # Stability
///
/// This vocabulary is **closed and append-only**. Adding a variant is routine.
/// **Renaming or removing one changes [`Kind::as_str`], hence
/// `structural_hash`, hence `finding_id`, hence every user's baselines and
/// suppressions** — that is on CLAUDE.md's stop-and-ask list and requires an
/// ADR. The string returned by [`Kind::as_str`] is the stable wire form; the
/// enum's declaration order and discriminants are not.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// Compilation unit / file root.
    Module,
    /// A statement sequence (function body, block, module body).
    Block,
    /// Function or method definition.
    Function,
    /// Lambda / arrow function.
    Lambda,
    /// Class definition.
    Class,
    /// Formal parameter.
    Parameter,
    /// Function or constructor invocation.
    Call,
    /// `new Foo()` — construction distinct from a plain call.
    New,
    /// One argument in a call.
    Argument,
    /// Bare name reference.
    Identifier,
    /// Attribute or property access (`a.b`).
    Attribute,
    /// Index or subscript access (`a[b]`).
    Subscript,
    /// String literal.
    StringLiteral,
    /// Numeric literal.
    NumberLiteral,
    /// Boolean literal.
    BoolLiteral,
    /// `None` / `null` / `undefined`.
    NullLiteral,
    /// Array / list / tuple literal.
    ArrayLiteral,
    /// Object / dict literal.
    ObjectLiteral,
    /// Assignment.
    Assignment,
    /// Binary operation.
    BinaryOp,
    /// Unary operation.
    UnaryOp,
    /// Conditional statement.
    If,
    /// Loop (`for`, `while`, comprehension driver).
    Loop,
    /// `try` / `catch` / `except` / `finally` construct.
    Try,
    /// Exception handler clause.
    Handler,
    /// `raise` / `throw`.
    Throw,
    /// `return`.
    Return,
    /// `await`.
    Await,
    /// `yield`.
    Yield,
    /// Module import in any spelling.
    Import,
    /// Decorator / annotation applied to a definition.
    Decorator,
    /// A construct the front-end recognized but has no canonical kind for.
    ///
    /// Deliberately coarse: an unmapped construct must never masquerade as a
    /// mapped one, because that would make two different constructs share a
    /// `structural_hash`.
    Other,
}

impl Kind {
    /// Whether this kind's [`Node::name`] holds a **literal value** rather than
    /// an identifier.
    ///
    /// Literal values are excluded from the hash basis (ADR 0016 decision 3:
    /// "raw literal text … excluded"), so rotating a URL, message or magic
    /// number does not churn `finding_id`. They are still used for *matching*,
    /// so a rule can pin `hashlib.new("md5")`.
    pub fn is_literal(self) -> bool {
        matches!(
            self,
            Kind::StringLiteral | Kind::NumberLiteral | Kind::BoolLiteral | Kind::NullLiteral
        )
    }

    /// The stable wire form. **This string is an identity input** — see the
    /// stability note on [`Kind`].
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Module => "module",
            Kind::Block => "block",
            Kind::Function => "function",
            Kind::Lambda => "lambda",
            Kind::Class => "class",
            Kind::Parameter => "parameter",
            Kind::Call => "call",
            Kind::New => "new",
            Kind::Argument => "argument",
            Kind::Identifier => "identifier",
            Kind::Attribute => "attribute",
            Kind::Subscript => "subscript",
            Kind::StringLiteral => "string_literal",
            Kind::NumberLiteral => "number_literal",
            Kind::BoolLiteral => "bool_literal",
            Kind::NullLiteral => "null_literal",
            Kind::ArrayLiteral => "array_literal",
            Kind::ObjectLiteral => "object_literal",
            Kind::Assignment => "assignment",
            Kind::BinaryOp => "binary_op",
            Kind::UnaryOp => "unary_op",
            Kind::If => "if",
            Kind::Loop => "loop",
            Kind::Try => "try",
            Kind::Handler => "handler",
            Kind::Throw => "throw",
            Kind::Return => "return",
            Kind::Await => "await",
            Kind::Yield => "yield",
            Kind::Import => "import",
            Kind::Decorator => "decorator",
            Kind::Other => "other",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Byte range in the source file, used for reporting only.
///
/// Spans are **never** part of identity (§7.7.3) — [`Node::structural_parts`]
/// does not read them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Span {
    /// Start byte offset.
    pub start: usize,
    /// End byte offset, exclusive.
    pub end: usize,
    /// 1-based line of `start`, for `Location.line`.
    pub line: u32,
}

/// A node in the common tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Node {
    /// Canonical kind.
    pub kind: Kind,
    /// Normalized identifier text, when the node names something.
    ///
    /// Identifiers, attribute selectors and literal values live here. **The two
    /// are treated differently downstream:** identifier-ish names feed
    /// `structural_hash`, literal values do not (see [`Kind::is_literal`] and
    /// ADR 0016), while *matching* is sensitive to both.
    ///
    /// Formatting-only detail must never be stored here.
    pub name: Option<String>,
    /// Child nodes, in source order.
    pub children: Vec<Node>,
    /// Source span, for reporting only.
    pub span: Span,
}

impl Node {
    /// A node with no children and no name.
    pub fn leaf(kind: Kind) -> Self {
        Node {
            kind,
            name: None,
            children: Vec::new(),
            span: Span::default(),
        }
    }

    /// A named leaf, e.g. an identifier.
    pub fn named(kind: Kind, name: impl Into<String>) -> Self {
        Node {
            kind,
            name: Some(name.into()),
            children: Vec::new(),
            span: Span::default(),
        }
    }

    /// Attach children, builder-style.
    pub fn with_children(mut self, children: Vec<Node>) -> Self {
        self.children = children;
        self
    }

    /// Attach a span, builder-style. Spans do not affect identity or matching.
    pub fn with_span(mut self, span: Span) -> Self {
        self.span = span;
        self
    }

    /// Pre-order traversal of canonical kinds and normalized identifiers, the
    /// exact basis `structural_hash` consumes (`docs/ms-pat-1.md` §5).
    ///
    /// Excluded, per ADR 0016 decision 3: spans (so a reformatted file keeps
    /// its `finding_id` — `SAST-002`) and **literal values** (so rotating a URL
    /// or message string does not churn identity). A literal still contributes
    /// its *kind*, so `f("a")` and `f(1)` remain distinct shapes.
    ///
    /// This is deliberately **not** the basis metavariable binding uses — see
    /// [`Node::structurally_eq`].
    pub fn structural_parts(&self) -> (Vec<&str>, Vec<&str>) {
        let mut kinds = Vec::new();
        let mut names = Vec::new();
        self.collect_parts(&mut kinds, &mut names);
        (kinds, names)
    }

    fn collect_parts<'a>(&'a self, kinds: &mut Vec<&'a str>, names: &mut Vec<&'a str>) {
        kinds.push(self.kind.as_str());
        if let Some(name) = &self.name {
            if !self.kind.is_literal() {
                names.push(name.as_str());
            }
        }
        for child in &self.children {
            child.collect_parts(kinds, names);
        }
    }

    /// Structural equality: kinds and names, ignoring spans.
    ///
    /// This is the equality metavariable binding uses, so `foo($X, $X)` matches
    /// `foo(a, a)` regardless of how the two `a`s are formatted.
    ///
    /// Unlike [`Node::structural_parts`], this **is** sensitive to literal
    /// values: `foo($X, $X)` must not match `foo("a", "b")`. Identity and
    /// matching answer different questions, so they use different bases.
    pub fn structurally_eq(&self, other: &Node) -> bool {
        self.kind == other.kind
            && self.name == other.name
            && self.children.len() == other.children.len()
            && self
                .children
                .iter()
                .zip(&other.children)
                .all(|(a, b)| a.structurally_eq(b))
    }

    /// Maximum depth of this subtree, for the recursion cap.
    pub fn depth(&self) -> usize {
        1 + self.children.iter().map(Node::depth).max().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call_foo_a() -> Node {
        Node::leaf(Kind::Call).with_children(vec![
            Node::named(Kind::Identifier, "foo"),
            Node::leaf(Kind::Argument).with_children(vec![Node::named(Kind::Identifier, "a")]),
        ])
    }

    #[test]
    fn structural_parts_are_preorder_and_span_free() {
        let tree = call_foo_a();
        let (kinds, names) = tree.structural_parts();
        assert_eq!(
            kinds,
            vec!["call", "identifier", "argument", "identifier"],
            "pre-order traversal is the frozen basis (ms-pat-1 §5)"
        );
        assert_eq!(names, vec!["foo", "a"]);
    }

    #[test]
    fn spans_change_nothing_structural() {
        // SAST-002 in its T-701-testable form: the same tree at different
        // source positions is the same structure. The full "reformat a real
        // source file" version needs a parser and lands with T-702.
        let mut moved = call_foo_a();
        moved.span = Span {
            start: 900,
            end: 999,
            line: 42,
        };
        moved.children[0].span = Span {
            start: 950,
            end: 953,
            line: 43,
        };

        let original = call_foo_a();
        assert_eq!(original.structural_parts(), moved.structural_parts());
        assert!(original.structurally_eq(&moved));
    }

    #[test]
    fn different_identifiers_are_not_structurally_equal() {
        let other = Node::leaf(Kind::Call).with_children(vec![
            Node::named(Kind::Identifier, "foo"),
            Node::leaf(Kind::Argument).with_children(vec![Node::named(Kind::Identifier, "b")]),
        ]);
        assert!(!call_foo_a().structurally_eq(&other));
    }

    #[test]
    fn kind_wire_forms_are_unique() {
        // A collision would make two different constructs share a
        // structural_hash. Guard the whole closed vocabulary at once.
        const ALL: &[Kind] = &[
            Kind::Module,
            Kind::Block,
            Kind::Function,
            Kind::Lambda,
            Kind::Class,
            Kind::Parameter,
            Kind::Call,
            Kind::New,
            Kind::Argument,
            Kind::Identifier,
            Kind::Attribute,
            Kind::Subscript,
            Kind::StringLiteral,
            Kind::NumberLiteral,
            Kind::BoolLiteral,
            Kind::NullLiteral,
            Kind::ArrayLiteral,
            Kind::ObjectLiteral,
            Kind::Assignment,
            Kind::BinaryOp,
            Kind::UnaryOp,
            Kind::If,
            Kind::Loop,
            Kind::Try,
            Kind::Handler,
            Kind::Throw,
            Kind::Return,
            Kind::Await,
            Kind::Yield,
            Kind::Import,
            Kind::Decorator,
            Kind::Other,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for kind in ALL {
            assert!(seen.insert(kind.as_str()), "duplicate wire form {kind}");
        }
        assert_eq!(seen.len(), ALL.len());
    }

    #[test]
    fn depth_counts_nesting() {
        assert_eq!(Node::leaf(Kind::Identifier).depth(), 1);
        assert_eq!(call_foo_a().depth(), 3);
    }
}
