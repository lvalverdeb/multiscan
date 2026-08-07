//! JavaScript/TypeScript front-end: `swc_ecma_parser` lowered into the common
//! tree. TypeScript rides the same front-end as JavaScript (ADR 0013).
//!
//! The `swc_*` types are confined to this module (ADR 0015 decision 5).

use swc_common::{sync::Lrc, FileName, SourceMap};
use swc_ecma_ast::{Callee, Decl, Expr, Lit, ModuleItem, Pat, Prop, PropOrSpread, Stmt};
use swc_ecma_parser::{lexer::Lexer, Parser, StringInput, Syntax, TsSyntax};

use super::{pattern_from_tree, substitute_placeholders, LineIndex, LowerError, MAX_SOURCE_BYTES};
use crate::pattern::PatternNode;
use crate::tree::{Kind, Node, Span};

/// File extensions this front-end claims (`SAST-003`).
pub const EXTENSIONS: &[&str] = &["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"];

/// Extensions that need the TypeScript grammar.
const TS_EXTENSIONS: &[&str] = &["ts", "tsx", "mts", "cts"];

/// Whether an extension should be parsed as TypeScript.
pub fn is_typescript(extension: &str) -> bool {
    TS_EXTENSIONS.contains(&extension)
}

/// Parse JavaScript/TypeScript source and lower it into the common tree.
///
/// `typescript` selects the grammar; JSX is enabled in both, since a `.js`
/// file containing JSX is common and failing on it would be a false negative.
pub fn lower_source(source: &str, typescript: bool) -> Result<Node, LowerError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(LowerError::TooLarge {
            size: source.len(),
            max: MAX_SOURCE_BYTES,
        });
    }

    let cm: Lrc<SourceMap> = Default::default();
    let fm = cm.new_source_file(FileName::Anon.into(), source.to_string());
    let syntax = if typescript {
        Syntax::Typescript(TsSyntax {
            tsx: true,
            ..Default::default()
        })
    } else {
        Syntax::Es(swc_ecma_parser::EsSyntax {
            jsx: true,
            ..Default::default()
        })
    };

    let lexer = Lexer::new(syntax, Default::default(), StringInput::from(&*fm), None);
    let mut parser = Parser::new_from(lexer);
    let module = parser.parse_module().map_err(|e| LowerError::Parse {
        language: "javascript",
        detail: format!("{:?}", e.kind()),
    })?;

    // swc recovers from many errors and still returns Ok, so a partially
    // understood file would otherwise scan as healthy and let the Engine report
    // Complete — which closes findings (§7.7.4). Treat recovered errors exactly
    // like a hard parse failure.
    let recovered = parser.take_errors();
    if let Some(first) = recovered.first() {
        return Err(LowerError::Parse {
            language: "javascript",
            detail: format!(
                "{} recovered parse error(s), first: {:?}",
                recovered.len(),
                first.kind()
            ),
        });
    }

    // swc positions are SourceMap-global; rebase to file-relative so spans are
    // comparable with every other engine's.
    let base = fm.start_pos.0 as usize;
    let index = LineIndex::new(source);
    let ctx = Ctx { base, index };

    let children = module
        .body
        .iter()
        .map(|item| match item {
            ModuleItem::Stmt(s) => ctx.stmt(s),
            ModuleItem::ModuleDecl(d) => ctx.module_decl(d),
        })
        .collect();

    Ok(Node::leaf(Kind::Module)
        .with_children(children)
        .with_span(Span {
            start: 0,
            end: source.len(),
            line: 1,
        }))
}

/// Compile MS-PAT-1 leaf pattern text into a [`PatternNode`].
pub fn compile_pattern(pattern_text: &str, typescript: bool) -> Result<PatternNode, LowerError> {
    let substituted = substitute_placeholders(pattern_text);
    let tree = lower_source(&substituted, typescript)?;
    super::single_construct(&tree, "javascript").map(pattern_from_tree)
}

use swc_common::Spanned;

struct Ctx {
    base: usize,
    index: LineIndex,
}

impl Ctx {
    fn span(&self, span: swc_common::Span) -> Span {
        let start = (span.lo.0 as usize).saturating_sub(self.base);
        let end = (span.hi.0 as usize).saturating_sub(self.base);
        Span {
            start,
            end,
            line: self.index.line(start),
        }
    }

    fn node(&self, kind: Kind, span: swc_common::Span, children: Vec<Node>) -> Node {
        Node {
            kind,
            name: None,
            children,
            span: self.span(span),
        }
    }

    fn named(
        &self,
        kind: Kind,
        name: impl Into<String>,
        span: swc_common::Span,
        children: Vec<Node>,
    ) -> Node {
        Node {
            kind,
            name: Some(name.into()),
            children,
            span: self.span(span),
        }
    }

    fn block(&self, stmts: &[Stmt], span: swc_common::Span) -> Node {
        self.node(
            Kind::Block,
            span,
            stmts.iter().map(|s| self.stmt(s)).collect(),
        )
    }

    /// Lower a module-level declaration.
    ///
    /// **Exported declarations must be seen through.** In ESM and TypeScript
    /// most top-level code is exported, so treating `export function f() {...}`
    /// as an opaque `Import` node would make the majority of a real repo
    /// invisible to matching — a silent false negative, not a degraded scan.
    fn module_decl(&self, decl: &swc_ecma_ast::ModuleDecl) -> Node {
        use swc_ecma_ast::{DefaultDecl, ModuleDecl};
        let span = decl.span();
        match decl {
            ModuleDecl::ExportDecl(e) => self.decl(&e.decl, span),
            ModuleDecl::ExportDefaultDecl(e) => match &e.decl {
                DefaultDecl::Fn(f) => {
                    let mut children: Vec<Node> = f
                        .function
                        .params
                        .iter()
                        .map(|p| self.param(&p.pat))
                        .collect();
                    if let Some(body) = &f.function.body {
                        children.push(self.block(&body.stmts, body.span));
                    }
                    match &f.ident {
                        Some(id) => self.named(Kind::Function, id.sym.as_str(), span, children),
                        None => self.node(Kind::Function, span, children),
                    }
                }
                DefaultDecl::Class(c) => self.class(&c.class, c.ident.as_ref(), span),
                DefaultDecl::TsInterfaceDecl(_) => self.node(Kind::Other, span, vec![]),
            },
            ModuleDecl::ExportDefaultExpr(e) => self.expr(&e.expr),
            // A real import/export-of-names statement carries no executable
            // body; it is an Import for reachability purposes (T-801).
            _ => self.node(Kind::Import, span, vec![]),
        }
    }

    /// Lower a class, including its method bodies.
    ///
    /// Method bodies are where the code lives; dropping them would make every
    /// class-based file invisible.
    fn class(
        &self,
        class: &swc_ecma_ast::Class,
        ident: Option<&swc_ecma_ast::Ident>,
        span: swc_common::Span,
    ) -> Node {
        use swc_ecma_ast::ClassMember;
        let children = class
            .body
            .iter()
            .filter_map(|member| match member {
                ClassMember::Method(m) => {
                    let mut kids: Vec<Node> = m
                        .function
                        .params
                        .iter()
                        .map(|p| self.param(&p.pat))
                        .collect();
                    if let Some(body) = &m.function.body {
                        kids.push(self.block(&body.stmts, body.span));
                    }
                    Some(match &m.key {
                        swc_ecma_ast::PropName::Ident(id) => {
                            self.named(Kind::Function, id.sym.as_str(), m.span, kids)
                        }
                        _ => self.node(Kind::Function, m.span, kids),
                    })
                }
                ClassMember::PrivateMethod(m) => {
                    let mut kids: Vec<Node> = m
                        .function
                        .params
                        .iter()
                        .map(|p| self.param(&p.pat))
                        .collect();
                    if let Some(body) = &m.function.body {
                        kids.push(self.block(&body.stmts, body.span));
                    }
                    Some(self.node(Kind::Function, m.span, kids))
                }
                ClassMember::Constructor(c) => {
                    let kids = c
                        .body
                        .as_ref()
                        .map(|b| vec![self.block(&b.stmts, b.span)])
                        .unwrap_or_default();
                    Some(self.named(Kind::Function, "constructor", c.span, kids))
                }
                ClassMember::ClassProp(p) => p
                    .value
                    .as_ref()
                    .map(|v| self.node(Kind::Assignment, p.span, vec![self.expr(v)])),
                ClassMember::PrivateProp(p) => p
                    .value
                    .as_ref()
                    .map(|v| self.node(Kind::Assignment, p.span, vec![self.expr(v)])),
                _ => None,
            })
            .collect();

        match ident {
            Some(id) => self.named(Kind::Class, id.sym.as_str(), span, children),
            None => self.node(Kind::Class, span, children),
        }
    }

    fn stmt(&self, stmt: &Stmt) -> Node {
        let span = stmt.span();
        match stmt {
            // Transparent, like Python: an expression statement is its
            // expression.
            Stmt::Expr(s) => self.expr(&s.expr),

            Stmt::Block(s) => self.block(&s.stmts, span),
            Stmt::Return(s) => self.node(
                Kind::Return,
                span,
                s.arg.iter().map(|a| self.expr(a)).collect(),
            ),
            Stmt::If(s) => {
                let mut children = vec![self.expr(&s.test), self.stmt(&s.cons)];
                if let Some(alt) = &s.alt {
                    children.push(self.stmt(alt));
                }
                self.node(Kind::If, span, children)
            }
            Stmt::While(s) => self.node(
                Kind::Loop,
                span,
                vec![self.expr(&s.test), self.stmt(&s.body)],
            ),
            Stmt::DoWhile(s) => self.node(
                Kind::Loop,
                span,
                vec![self.expr(&s.test), self.stmt(&s.body)],
            ),
            Stmt::For(s) => self.node(Kind::Loop, span, vec![self.stmt(&s.body)]),
            Stmt::ForIn(s) => self.node(
                Kind::Loop,
                span,
                vec![self.expr(&s.right), self.stmt(&s.body)],
            ),
            Stmt::ForOf(s) => self.node(
                Kind::Loop,
                span,
                vec![self.expr(&s.right), self.stmt(&s.body)],
            ),
            Stmt::Throw(s) => self.node(Kind::Throw, span, vec![self.expr(&s.arg)]),
            Stmt::Try(s) => {
                let mut children = vec![self.block(&s.block.stmts, s.block.span)];
                if let Some(handler) = &s.handler {
                    children.push(self.node(
                        Kind::Handler,
                        handler.span,
                        vec![self.block(&handler.body.stmts, handler.body.span)],
                    ));
                }
                if let Some(finalizer) = &s.finalizer {
                    children.push(self.block(&finalizer.stmts, finalizer.span));
                }
                self.node(Kind::Try, span, children)
            }
            Stmt::Decl(d) => self.decl(d, span),
            _ => self.node(Kind::Other, span, vec![]),
        }
    }

    fn decl(&self, decl: &Decl, span: swc_common::Span) -> Node {
        match decl {
            Decl::Fn(f) => {
                let mut children: Vec<Node> = f
                    .function
                    .params
                    .iter()
                    .map(|p| self.param(&p.pat))
                    .collect();
                if let Some(body) = &f.function.body {
                    children.push(self.block(&body.stmts, body.span));
                }
                self.named(Kind::Function, f.ident.sym.as_str(), span, children)
            }
            Decl::Class(c) => self.class(&c.class, Some(&c.ident), span),
            Decl::Var(v) => {
                let children = v
                    .decls
                    .iter()
                    .map(|d| {
                        let mut kids = vec![self.param(&d.name)];
                        if let Some(init) = &d.init {
                            kids.push(self.expr(init));
                        }
                        self.node(Kind::Assignment, d.span, kids)
                    })
                    .collect();
                self.node(Kind::Block, span, children)
            }
            _ => self.node(Kind::Other, span, vec![]),
        }
    }

    fn param(&self, pat: &Pat) -> Node {
        match pat {
            Pat::Ident(id) => self.named(Kind::Parameter, id.id.sym.as_str(), id.span, vec![]),
            _ => self.node(Kind::Parameter, pat.span(), vec![]),
        }
    }

    fn expr(&self, expr: &Expr) -> Node {
        let span = expr.span();
        match expr {
            Expr::Ident(id) => self.named(Kind::Identifier, id.sym.as_str(), span, vec![]),

            Expr::Call(c) => {
                let mut children = match &c.callee {
                    Callee::Expr(e) => vec![self.expr(e)],
                    _ => vec![self.node(Kind::Other, span, vec![])],
                };
                children.extend(
                    c.args
                        .iter()
                        .map(|a| self.node(Kind::Argument, a.span(), vec![self.expr(&a.expr)])),
                );
                self.node(Kind::Call, span, children)
            }

            Expr::New(n) => {
                let mut children = vec![self.expr(&n.callee)];
                if let Some(args) = &n.args {
                    children
                        .extend(args.iter().map(|a| {
                            self.node(Kind::Argument, a.span(), vec![self.expr(&a.expr)])
                        }));
                }
                self.node(Kind::New, span, children)
            }

            Expr::Member(m) => {
                let value = self.expr(&m.obj);
                match &m.prop {
                    swc_ecma_ast::MemberProp::Ident(id) => {
                        self.named(Kind::Attribute, id.sym.as_str(), span, vec![value])
                    }
                    swc_ecma_ast::MemberProp::Computed(c) => {
                        self.node(Kind::Subscript, span, vec![value, self.expr(&c.expr)])
                    }
                    swc_ecma_ast::MemberProp::PrivateName(_) => {
                        self.node(Kind::Attribute, span, vec![value])
                    }
                }
            }

            Expr::Lit(lit) => match lit {
                Lit::Str(s) => self.named(
                    Kind::StringLiteral,
                    s.value.as_str().unwrap_or_default(),
                    span,
                    vec![],
                ),
                Lit::Num(_) | Lit::BigInt(_) => self.node(Kind::NumberLiteral, span, vec![]),
                Lit::Bool(b) => self.named(
                    Kind::BoolLiteral,
                    if b.value { "true" } else { "false" },
                    span,
                    vec![],
                ),
                Lit::Null(_) => self.node(Kind::NullLiteral, span, vec![]),
                Lit::Regex(_) | Lit::JSXText(_) => self.node(Kind::Other, span, vec![]),
            },

            Expr::Array(a) => self.node(
                Kind::ArrayLiteral,
                span,
                a.elems
                    .iter()
                    .flatten()
                    .map(|e| self.expr(&e.expr))
                    .collect(),
            ),
            Expr::Object(o) => self.node(
                Kind::ObjectLiteral,
                span,
                o.props
                    .iter()
                    .filter_map(|p| match p {
                        PropOrSpread::Prop(prop) => match &**prop {
                            Prop::KeyValue(kv) => Some(self.expr(&kv.value)),
                            _ => None,
                        },
                        PropOrSpread::Spread(s) => Some(self.expr(&s.expr)),
                    })
                    .collect(),
            ),

            Expr::Assign(a) => self.node(Kind::Assignment, span, vec![self.expr(&a.right)]),
            Expr::Bin(b) => self.node(
                Kind::BinaryOp,
                span,
                vec![self.expr(&b.left), self.expr(&b.right)],
            ),
            Expr::Unary(u) => self.node(Kind::UnaryOp, span, vec![self.expr(&u.arg)]),
            Expr::Update(u) => self.node(Kind::UnaryOp, span, vec![self.expr(&u.arg)]),
            Expr::Cond(c) => self.node(
                Kind::If,
                span,
                vec![self.expr(&c.test), self.expr(&c.cons), self.expr(&c.alt)],
            ),
            Expr::Await(a) => self.node(Kind::Await, span, vec![self.expr(&a.arg)]),
            Expr::Yield(y) => self.node(
                Kind::Yield,
                span,
                y.arg.iter().map(|a| self.expr(a)).collect(),
            ),

            Expr::Arrow(a) => {
                let mut children: Vec<Node> = a.params.iter().map(|p| self.param(p)).collect();
                if let swc_ecma_ast::BlockStmtOrExpr::BlockStmt(b) = &*a.body {
                    children.push(self.block(&b.stmts, b.span));
                } else if let swc_ecma_ast::BlockStmtOrExpr::Expr(e) = &*a.body {
                    children.push(self.expr(e));
                }
                self.node(Kind::Lambda, span, children)
            }
            Expr::Fn(f) => {
                let mut children: Vec<Node> = f
                    .function
                    .params
                    .iter()
                    .map(|p| self.param(&p.pat))
                    .collect();
                if let Some(body) = &f.function.body {
                    children.push(self.block(&body.stmts, body.span));
                }
                self.node(Kind::Lambda, span, children)
            }

            // Parenthesis is formatting, not structure — see through it, or
            // `eval((x))` would not match `eval(x)` (SAST-002).
            Expr::Paren(p) => self.expr(&p.expr),
            // A TypeScript assertion is a type-level wrapper; the value beneath
            // is what matters structurally.
            Expr::TsAs(t) => self.expr(&t.expr),
            Expr::TsNonNull(t) => self.expr(&t.expr),
            Expr::TsSatisfies(t) => self.expr(&t.expr),

            _ => self.node(Kind::Other, span, vec![]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::matches;
    use crate::pattern::PatternExpr;
    use crate::structural_hash_of;

    fn js(src: &str) -> Node {
        lower_source(src, false).unwrap()
    }

    #[test]
    fn lowers_a_call() {
        let tree = js("eval(userInput);\n");
        let (kinds, names) = tree.structural_parts();
        assert_eq!(
            kinds,
            vec!["module", "call", "identifier", "argument", "identifier"]
        );
        assert_eq!(names, vec!["eval", "userInput"]);
    }

    #[test]
    fn compiles_a_pattern_and_matches_real_source() {
        let expr = PatternExpr::Pattern(compile_pattern("eval($X)", false).unwrap());
        let tree = js("eval(userInput);\n");
        let found = matches(&expr, &tree);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].bindings["X"].name.as_deref(), Some("userInput"));
    }

    #[test]
    fn member_calls_lower_with_the_selector() {
        let expr = PatternExpr::Pattern(compile_pattern("child_process.exec($X)", false).unwrap());
        assert_eq!(matches(&expr, &js("child_process.exec(cmd);\n")).len(), 1);
        assert!(matches(&expr, &js("other.exec(cmd);\n")).is_empty());
    }

    #[test]
    fn reformatting_preserves_the_structural_hash() {
        // SAST-002 on real source, JS side.
        let compact = js("function f(a){return eval(a);}\n");
        let spaced = js("\n// comment\nfunction f( a ) {\n\n    return eval( a );\n\n}\n");
        assert_eq!(structural_hash_of(&compact), structural_hash_of(&spaced));
    }

    #[test]
    fn parentheses_are_formatting_not_structure() {
        // Redundant parens must not change identity, or a reformat would.
        assert_eq!(
            structural_hash_of(&js("eval(x);\n")),
            structural_hash_of(&js("eval((x));\n"))
        );
    }

    #[test]
    fn typescript_parses_through_the_same_front_end() {
        let tree = lower_source("const x: string = evil(y as any);\n", true).unwrap();
        let expr = PatternExpr::Pattern(compile_pattern("evil($X)", true).unwrap());
        assert_eq!(matches(&expr, &tree).len(), 1);
    }

    #[test]
    fn typescript_assertions_do_not_change_identity() {
        let plain = lower_source("evil(y);\n", true).unwrap();
        let asserted = lower_source("evil(y as any);\n", true).unwrap();
        assert_eq!(structural_hash_of(&plain), structural_hash_of(&asserted));
    }

    #[test]
    fn ellipsis_matches_any_arity() {
        let expr = PatternExpr::Pattern(compile_pattern("eval(...)", false).unwrap());
        for src in ["eval();", "eval(a);", "eval(a, b, c);"] {
            assert_eq!(matches(&expr, &js(src)).len(), 1, "failed on {src}");
        }
    }

    #[test]
    fn syntax_errors_are_an_error_not_a_panic() {
        assert!(lower_source("function (", false).is_err());
    }

    #[test]
    fn exported_declarations_are_seen_through() {
        // In ESM and TypeScript most top-level code is exported. Treating an
        // export as an opaque node would make the majority of a real repo
        // invisible — a silent false negative.
        let expr = PatternExpr::Pattern(compile_pattern("eval($X)", false).unwrap());

        for src in [
            "export function handler(req) { eval(req.body); }\n",
            "export default function handler(req) { eval(req.body); }\n",
            "export const f = (req) => { eval(req.body); };\n",
            "export class C { m(req) { eval(req.body); } }\n",
        ] {
            let tree = js(src);
            assert_eq!(matches(&expr, &tree).len(), 1, "missed a match in: {src}");
        }
    }

    #[test]
    fn class_method_bodies_are_lowered() {
        // Dropping class members would make every class-based file invisible.
        let expr = PatternExpr::Pattern(compile_pattern("eval($X)", false).unwrap());

        for src in [
            "class C { m(x) { eval(x); } }\n",
            "class C { constructor(x) { eval(x); } }\n",
            "class C { #priv(x) { eval(x); } }\n",
            "class C { prop = eval(x); }\n",
        ] {
            let tree = js(src);
            assert_eq!(matches(&expr, &tree).len(), 1, "missed a match in: {src}");
        }
    }

    #[test]
    fn plain_imports_still_lower_as_imports() {
        // Export-of-declaration is seen through; a bare import/export of names
        // carries no executable body and stays an Import (for T-801).
        let tree = js("import fs from 'fs';\nexport { a };\n");
        let kinds: Vec<_> = tree.children.iter().map(|c| c.kind).collect();
        assert_eq!(kinds, vec![Kind::Import, Kind::Import]);
    }

    #[test]
    fn recovered_parse_errors_degrade_the_file() {
        // swc recovers from many errors and still returns Ok. A partially
        // understood file must not scan as healthy, or the Engine reports
        // Complete and closes findings (§7.7.4).
        let recovered = lower_source("class { eval(x); }\n", false);
        assert!(
            recovered.is_err(),
            "a file swc only partly understood must not pass as healthy"
        );
    }

    #[test]
    fn multi_statement_leaf_patterns_are_rejected() {
        // Would otherwise compile to a Module pattern matchable only at file
        // root — silently never matching what the author meant.
        let err = compile_pattern("eval(x); eval(y);", false).unwrap_err();
        assert!(err.to_string().contains("single construct"), "got: {err}");
    }

    #[test]
    fn extension_routing_picks_the_typescript_grammar() {
        assert!(is_typescript("ts"));
        assert!(is_typescript("tsx"));
        assert!(!is_typescript("js"));
        assert!(!is_typescript("jsx"));
    }
}
