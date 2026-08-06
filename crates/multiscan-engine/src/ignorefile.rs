//! Ignore-file matching (`.multiscanignore`, optionally `.gitignore` —
//! ADR 0009). A focused, gitignore-syntax subset compiled onto `globset`:
//! comments, blank lines, `!` negation (last match wins), trailing-slash
//! directory-only rules, leading-slash / embedded-slash anchoring, and
//! `*`/`?`/`**` globs. Matching is against root-relative POSIX paths (DET-005).
//!
//! This is convenience filtering, not a security boundary — see ADR 0009 for
//! why `.gitignore` reuse is opt-in (a secrets scan must not skip a gitignored
//! `.env` by default).

use globset::{GlobBuilder, GlobMatcher};

/// One compiled ignore rule.
#[derive(Debug, Clone)]
struct Rule {
    /// `!pattern` — re-includes an otherwise-ignored path.
    negated: bool,
    /// Trailing-slash pattern: the rule's own entry matches only directories.
    dir_only: bool,
    /// Matches the path itself (`foo`, `a/b`).
    own: GlobMatcher,
    /// Matches anything beneath it (`foo/**`) so ignoring a dir ignores its
    /// contents even when the walker sees the file before pruning.
    children: GlobMatcher,
}

impl Rule {
    fn matches(&self, rel: &str, is_dir: bool) -> bool {
        (self.own.is_match(rel) && (!self.dir_only || is_dir)) || self.children.is_match(rel)
    }
}

/// A compiled set of ignore rules, evaluated in order (last match wins, as in
/// gitignore).
#[derive(Debug, Clone, Default)]
pub struct IgnoreSet {
    rules: Vec<Rule>,
}

fn compile_glob(pattern: &str) -> Option<GlobMatcher> {
    GlobBuilder::new(pattern)
        // `*` must not cross `/`; `**` still spans segments.
        .literal_separator(true)
        .build()
        .ok()
        .map(|g| g.compile_matcher())
}

impl IgnoreSet {
    /// Compile the concatenated text of one or more ignore files. Unparseable
    /// individual patterns are skipped (an ignore file is convenience, never a
    /// hard failure); everything else still applies.
    pub fn parse(text: &str) -> Self {
        let mut rules = Vec::new();
        for raw in text.lines() {
            let line = raw.trim_end();
            // Comments and blanks. A leading `\#`/`\!` escapes the marker.
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let mut pat = line;
            let negated = pat.starts_with('!');
            if negated {
                pat = &pat[1..];
            }
            // Trailing slash ⇒ directory-only.
            let dir_only = pat.ends_with('/');
            let pat = pat.trim_end_matches('/');
            if pat.is_empty() {
                continue;
            }
            // Anchored when a slash appears anywhere but the (already stripped)
            // trailing one; otherwise the rule matches at any depth.
            let anchored = pat.contains('/');
            let base = if anchored {
                pat.strip_prefix('/').unwrap_or(pat).to_string()
            } else {
                format!("**/{pat}")
            };
            let (Some(own), Some(children)) =
                (compile_glob(&base), compile_glob(&format!("{base}/**")))
            else {
                continue;
            };
            rules.push(Rule {
                negated,
                dir_only,
                own,
                children,
            });
        }
        Self { rules }
    }

    /// True when no rule applies.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether `rel` (root-relative POSIX; `is_dir` flags directories) is
    /// ignored. Later rules override earlier ones, so a `!` negation can
    /// re-include a path an earlier rule excluded.
    pub fn is_ignored(&self, rel: &str, is_dir: bool) -> bool {
        let mut ignored = false;
        for rule in &self.rules {
            if rule.matches(rel, is_dir) {
                ignored = !rule.negated;
            }
        }
        ignored
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_blanks_ignored() {
        let s = IgnoreSet::parse("# a comment\n\n   \n");
        assert!(s.is_empty());
    }

    #[test]
    fn unanchored_matches_any_depth() {
        let s = IgnoreSet::parse("node_modules/\n*.log\n");
        assert!(s.is_ignored("node_modules", true));
        assert!(s.is_ignored("sub/node_modules", true));
        assert!(s.is_ignored("sub/node_modules/pkg/index.js", false));
        assert!(s.is_ignored("app/debug.log", false));
        assert!(!s.is_ignored("src/main.rs", false));
    }

    #[test]
    fn directory_only_rule_needs_a_dir() {
        let s = IgnoreSet::parse("build/\n");
        assert!(s.is_ignored("build", true));
        // A *file* literally named `build` is not matched by `build/`…
        assert!(!s.is_ignored("build", false));
        // …but contents of a build directory are.
        assert!(s.is_ignored("build/out.o", false));
    }

    #[test]
    fn anchored_rule_binds_to_root() {
        let s = IgnoreSet::parse("/dist\n");
        assert!(s.is_ignored("dist", true));
        assert!(s.is_ignored("dist/bundle.js", false));
        // Not anchored elsewhere.
        assert!(!s.is_ignored("packages/dist", true));
    }

    #[test]
    fn negation_reincludes() {
        let s = IgnoreSet::parse("*.env\n!.env.example\n");
        assert!(s.is_ignored("config/.prod.env", false));
        assert!(!s.is_ignored(".env.example", false), "negation must win");
    }

    #[test]
    fn star_does_not_cross_slash() {
        let s = IgnoreSet::parse("logs/*.txt\n");
        assert!(s.is_ignored("logs/a.txt", false));
        // `*` stays within a segment.
        assert!(!s.is_ignored("logs/sub/a.txt", false));
    }
}
