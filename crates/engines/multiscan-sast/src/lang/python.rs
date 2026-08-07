//! Python front-end: `ruff_python_parser` lowered into the common tree.
//!
//! The `ruff_*` types are confined to this module (ADR 0015 decision 5). They
//! are a `0.0.x` dependency with no semver guarantee, so an upstream AST
//! reshaping must be a contained edit here, never a matcher rewrite.

use ruff_python_ast::{Expr, Mod, Stmt};
use ruff_text_size::Ranged;

use super::{pattern_from_tree, substitute_placeholders, LineIndex, LowerError, MAX_SOURCE_BYTES};
use crate::pattern::PatternNode;
use crate::tree::{Kind, Node, Span};

/// File extensions this front-end claims.
///
/// Used by `applicable()`, which must stay extension-only — no file reads
/// (`SAST-003`, ENG contract).
pub const EXTENSIONS: &[&str] = &["py", "pyi"];

/// Parse Python source and lower it into the common tree.
pub fn lower_source(source: &str) -> Result<Node, LowerError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(LowerError::TooLarge {
            size: source.len(),
            max: MAX_SOURCE_BYTES,
        });
    }
    let parsed = ruff_python_parser::parse_module(source).map_err(|e| LowerError::Parse {
        language: "python",
        detail: e.to_string(),
    })?;

    let index = LineIndex::new(source);
    let module = parsed.syntax();
    let children = module.body.iter().map(|s| lower_stmt(s, &index)).collect();

    Ok(Node::leaf(Kind::Module)
        .with_children(children)
        .with_span(span_of(0, source.len(), &index)))
}

/// Compile MS-PAT-1 leaf pattern text into a [`PatternNode`].
///
/// Substitute holes, parse with the real parser, lower with the same function
/// as source, then convert placeholders back — see `lang` module docs.
pub fn compile_pattern(pattern_text: &str) -> Result<PatternNode, LowerError> {
    let substituted = substitute_placeholders(pattern_text);
    let tree = lower_source(&substituted)?;
    super::single_construct(&tree, "python").map(pattern_from_tree)
}

fn span_of(start: usize, end: usize, index: &LineIndex) -> Span {
    Span {
        start,
        end,
        line: index.line(start),
    }
}

fn ranged_span<T: Ranged>(node: &T, index: &LineIndex) -> Span {
    let range = node.range();
    span_of(range.start().to_usize(), range.end().to_usize(), index)
}

fn node(kind: Kind, span: Span, children: Vec<Node>) -> Node {
    Node {
        kind,
        name: None,
        children,
        span,
    }
}

fn named_node(kind: Kind, name: impl Into<String>, span: Span, children: Vec<Node>) -> Node {
    Node {
        kind,
        name: Some(name.into()),
        children,
        span,
    }
}

fn block(stmts: &[Stmt], index: &LineIndex) -> Node {
    let children: Vec<Node> = stmts.iter().map(|s| lower_stmt(s, index)).collect();
    let span = children
        .first()
        .map(|c| Span {
            start: c.span.start,
            end: children.last().map(|l| l.span.end).unwrap_or(c.span.end),
            line: c.span.line,
        })
        .unwrap_or_default();
    node(Kind::Block, span, children)
}

fn lower_stmt(stmt: &Stmt, index: &LineIndex) -> Node {
    let span = ranged_span(stmt, index);
    match stmt {
        // Transparent: an expression statement is its expression, so `eval($X)`
        // matches whether it is a statement or nested in one.
        Stmt::Expr(s) => lower_expr(&s.value, index),

        Stmt::FunctionDef(s) => {
            let mut children: Vec<Node> = s
                .decorator_list
                .iter()
                .map(|d| {
                    node(
                        Kind::Decorator,
                        ranged_span(d, index),
                        vec![lower_expr(&d.expression, index)],
                    )
                })
                .collect();
            children.extend(s.parameters.iter().map(|p| {
                named_node(
                    Kind::Parameter,
                    p.name().as_str(),
                    ranged_span(&p, index),
                    vec![],
                )
            }));
            children.push(block(&s.body, index));
            named_node(Kind::Function, s.name.as_str(), span, children)
        }

        Stmt::ClassDef(s) => {
            let mut children: Vec<Node> = s
                .decorator_list
                .iter()
                .map(|d| {
                    node(
                        Kind::Decorator,
                        ranged_span(d, index),
                        vec![lower_expr(&d.expression, index)],
                    )
                })
                .collect();
            children.push(block(&s.body, index));
            named_node(Kind::Class, s.name.as_str(), span, children)
        }

        Stmt::Return(s) => node(
            Kind::Return,
            span,
            s.value.iter().map(|v| lower_expr(v, index)).collect(),
        ),

        Stmt::Assign(s) => {
            let mut children: Vec<Node> = s.targets.iter().map(|t| lower_expr(t, index)).collect();
            children.push(lower_expr(&s.value, index));
            node(Kind::Assignment, span, children)
        }
        Stmt::AugAssign(s) => node(
            Kind::Assignment,
            span,
            vec![lower_expr(&s.target, index), lower_expr(&s.value, index)],
        ),
        Stmt::AnnAssign(s) => {
            let mut children = vec![lower_expr(&s.target, index)];
            children.extend(s.value.iter().map(|v| lower_expr(v, index)));
            node(Kind::Assignment, span, children)
        }

        Stmt::For(s) => node(
            Kind::Loop,
            span,
            vec![
                lower_expr(&s.target, index),
                lower_expr(&s.iter, index),
                block(&s.body, index),
            ],
        ),
        Stmt::While(s) => node(
            Kind::Loop,
            span,
            vec![lower_expr(&s.test, index), block(&s.body, index)],
        ),

        Stmt::If(s) => {
            let mut children = vec![lower_expr(&s.test, index), block(&s.body, index)];
            for clause in &s.elif_else_clauses {
                children.push(block(&clause.body, index));
            }
            node(Kind::If, span, children)
        }

        Stmt::Try(s) => {
            let mut children = vec![block(&s.body, index)];
            for handler in &s.handlers {
                let ruff_python_ast::ExceptHandler::ExceptHandler(h) = handler;
                children.push(node(
                    Kind::Handler,
                    ranged_span(handler, index),
                    vec![block(&h.body, index)],
                ));
            }
            if !s.orelse.is_empty() {
                children.push(block(&s.orelse, index));
            }
            if !s.finalbody.is_empty() {
                children.push(block(&s.finalbody, index));
            }
            node(Kind::Try, span, children)
        }

        Stmt::Raise(s) => node(
            Kind::Throw,
            span,
            s.exc.iter().map(|e| lower_expr(e, index)).collect(),
        ),

        Stmt::Import(s) => {
            let children = s
                .names
                .iter()
                .map(|a| {
                    named_node(
                        Kind::Identifier,
                        a.name.as_str(),
                        ranged_span(a, index),
                        vec![],
                    )
                })
                .collect();
            node(Kind::Import, span, children)
        }
        Stmt::ImportFrom(s) => {
            let module = s.module.as_ref().map(|m| m.as_str()).unwrap_or("");
            let children = s
                .names
                .iter()
                .map(|a| {
                    named_node(
                        Kind::Identifier,
                        a.name.as_str(),
                        ranged_span(a, index),
                        vec![],
                    )
                })
                .collect();
            named_node(Kind::Import, module, span, children)
        }

        Stmt::With(s) => node(Kind::Other, span, vec![block(&s.body, index)]),

        // Deliberately coarse: an unmapped construct must never masquerade as a
        // mapped one, or two different constructs would share a
        // structural_hash (ADR 0016).
        _ => node(Kind::Other, span, vec![]),
    }
}

fn lower_expr(expr: &Expr, index: &LineIndex) -> Node {
    let span = ranged_span(expr, index);
    match expr {
        Expr::Name(e) => named_node(Kind::Identifier, e.id.as_str(), span, vec![]),

        Expr::Call(e) => {
            let mut children = vec![lower_expr(&e.func, index)];
            children.extend(e.arguments.args.iter().map(|a| {
                node(
                    Kind::Argument,
                    ranged_span(a, index),
                    vec![lower_expr(a, index)],
                )
            }));
            children.extend(e.arguments.keywords.iter().map(|k| {
                let inner = lower_expr(&k.value, index);
                match &k.arg {
                    Some(name) => named_node(
                        Kind::Argument,
                        name.as_str(),
                        ranged_span(k, index),
                        vec![inner],
                    ),
                    None => node(Kind::Argument, ranged_span(k, index), vec![inner]),
                }
            }));
            node(Kind::Call, span, children)
        }

        Expr::Attribute(e) => named_node(
            Kind::Attribute,
            e.attr.as_str(),
            span,
            vec![lower_expr(&e.value, index)],
        ),
        Expr::Subscript(e) => node(
            Kind::Subscript,
            span,
            vec![lower_expr(&e.value, index), lower_expr(&e.slice, index)],
        ),

        Expr::StringLiteral(e) => named_node(Kind::StringLiteral, e.value.to_str(), span, vec![]),
        Expr::NumberLiteral(_) => node(Kind::NumberLiteral, span, vec![]),
        Expr::BooleanLiteral(e) => named_node(
            Kind::BoolLiteral,
            if e.value { "true" } else { "false" },
            span,
            vec![],
        ),
        Expr::NoneLiteral(_) => node(Kind::NullLiteral, span, vec![]),

        Expr::List(e) => node(
            Kind::ArrayLiteral,
            span,
            e.elts.iter().map(|x| lower_expr(x, index)).collect(),
        ),
        Expr::Tuple(e) => node(
            Kind::ArrayLiteral,
            span,
            e.elts.iter().map(|x| lower_expr(x, index)).collect(),
        ),
        Expr::Set(e) => node(
            Kind::ArrayLiteral,
            span,
            e.elts.iter().map(|x| lower_expr(x, index)).collect(),
        ),
        Expr::Dict(e) => node(
            Kind::ObjectLiteral,
            span,
            e.items
                .iter()
                .map(|item| lower_expr(&item.value, index))
                .collect(),
        ),

        Expr::BinOp(e) => node(
            Kind::BinaryOp,
            span,
            vec![lower_expr(&e.left, index), lower_expr(&e.right, index)],
        ),
        Expr::BoolOp(e) => node(
            Kind::BinaryOp,
            span,
            e.values.iter().map(|v| lower_expr(v, index)).collect(),
        ),
        Expr::Compare(e) => {
            let mut children = vec![lower_expr(&e.left, index)];
            children.extend(e.comparators.iter().map(|c| lower_expr(c, index)));
            node(Kind::BinaryOp, span, children)
        }
        Expr::UnaryOp(e) => node(Kind::UnaryOp, span, vec![lower_expr(&e.operand, index)]),

        Expr::Lambda(e) => node(Kind::Lambda, span, vec![lower_expr(&e.body, index)]),
        Expr::Await(e) => node(Kind::Await, span, vec![lower_expr(&e.value, index)]),
        Expr::Yield(e) => node(
            Kind::Yield,
            span,
            e.value.iter().map(|v| lower_expr(v, index)).collect(),
        ),
        Expr::YieldFrom(e) => node(Kind::Yield, span, vec![lower_expr(&e.value, index)]),
        Expr::Starred(e) => lower_expr(&e.value, index),

        Expr::If(e) => node(
            Kind::If,
            span,
            vec![
                lower_expr(&e.test, index),
                lower_expr(&e.body, index),
                lower_expr(&e.orelse, index),
            ],
        ),

        _ => node(Kind::Other, span, vec![]),
    }
}

/// Lower a parsed module for callers that already hold one. Kept private-ish so
/// `Mod` does not leak; used only by the source path above.
#[allow(dead_code)]
fn module_body(module: &Mod) -> &[Stmt] {
    match module {
        Mod::Module(m) => &m.body,
        Mod::Expression(_) => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::matches;
    use crate::pattern::PatternExpr;
    use crate::structural_hash_of;

    #[test]
    fn lowers_a_call() {
        let tree = lower_source("eval(user_input)\n").unwrap();
        let (kinds, names) = tree.structural_parts();
        assert_eq!(
            kinds,
            vec!["module", "call", "identifier", "argument", "identifier"]
        );
        assert_eq!(names, vec!["eval", "user_input"]);
    }

    #[test]
    fn compiles_a_pattern_and_matches_real_source() {
        let pattern = compile_pattern("eval($X)").unwrap();
        let expr = PatternExpr::Pattern(pattern);
        let tree = lower_source("eval(user_input)\n").unwrap();

        let found = matches(&expr, &tree);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].bindings["X"].name.as_deref(),
            Some("user_input"),
            "$X binds the argument"
        );
    }

    #[test]
    fn ellipsis_pattern_matches_any_arity() {
        let expr = PatternExpr::Pattern(compile_pattern("eval(...)").unwrap());
        for src in ["eval()", "eval(a)", "eval(a, b, c)"] {
            let tree = lower_source(src).unwrap();
            assert_eq!(matches(&expr, &tree).len(), 1, "failed on {src}");
        }
    }

    #[test]
    fn reformatting_preserves_the_structural_hash() {
        // SAST-002, in the literal form T-701 could not test: real source,
        // reformatted, must produce the same identity.
        let compact = lower_source("def f(a):\n    return eval(a)\n").unwrap();
        let spaced =
            lower_source("\n\n# a comment\ndef f( a ):\n\n        return eval(  a  )\n\n").unwrap();

        assert_eq!(
            structural_hash_of(&compact),
            structural_hash_of(&spaced),
            "reformatting must not change structural_hash"
        );
    }

    #[test]
    fn renaming_does_change_the_hash() {
        // The companion near-miss: identifiers are identity, formatting is not.
        let a = lower_source("eval(a)\n").unwrap();
        let b = lower_source("eval(b)\n").unwrap();
        assert_ne!(structural_hash_of(&a), structural_hash_of(&b));
    }

    #[test]
    fn attribute_calls_lower_with_the_selector() {
        let expr = PatternExpr::Pattern(compile_pattern("os.system($X)").unwrap());
        let tree = lower_source("os.system(cmd)\n").unwrap();
        assert_eq!(matches(&expr, &tree).len(), 1);

        // A different module must not match.
        let other = lower_source("subprocess.system(cmd)\n").unwrap();
        assert!(matches(&expr, &other).is_empty());
    }

    #[test]
    fn pattern_inside_a_function_scopes_the_match() {
        let expr = PatternExpr::All(vec![
            PatternExpr::Pattern(compile_pattern("eval($X)").unwrap()),
            PatternExpr::Inside(Box::new(PatternExpr::Pattern(
                compile_pattern("def handler(): ...").unwrap(),
            ))),
        ]);

        let inside = lower_source("def handler():\n    eval(x)\n").unwrap();
        let outside = lower_source("def other():\n    eval(x)\n").unwrap();

        assert_eq!(matches(&expr, &inside).len(), 1);
        assert!(matches(&expr, &outside).is_empty());
    }

    #[test]
    fn syntax_errors_are_an_error_not_a_panic() {
        // A malformed file in someone's repo degrades the scan, never aborts it.
        assert!(lower_source("def (:\n").is_err());
    }

    #[test]
    fn class_method_bodies_are_lowered() {
        // The Python counterpart of the JS class hole.
        let expr = PatternExpr::Pattern(compile_pattern("eval($X)").unwrap());
        let tree = lower_source("class C:\n    def m(self, x):\n        eval(x)\n").unwrap();
        assert_eq!(matches(&expr, &tree).len(), 1);
    }

    #[test]
    fn multi_statement_leaf_patterns_are_rejected() {
        // Would compile to a Module pattern matchable only at file root.
        let err = compile_pattern("eval(x)\neval(y)\n").unwrap_err();
        assert!(err.to_string().contains("single construct"), "got: {err}");
    }

    #[test]
    fn oversized_source_is_rejected() {
        let huge = "x = 1\n".repeat(MAX_SOURCE_BYTES / 6 + 10);
        assert!(matches!(
            lower_source(&huge),
            Err(LowerError::TooLarge { .. })
        ));
    }

    #[test]
    fn reserved_prefix_in_real_source_is_just_an_identifier() {
        // Only pattern text is substituted (ms-pat-1 §3), so a variable that
        // happens to be called __ms_metavar_X must not become a metavariable.
        let expr = PatternExpr::Pattern(compile_pattern("eval($X)").unwrap());
        let tree = lower_source("eval(__ms_metavar_X)\n").unwrap();
        let found = matches(&expr, &tree);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].bindings["X"].name.as_deref(),
            Some("__ms_metavar_X"),
            "the source identifier is bound as data, not treated as a hole"
        );
    }
}
