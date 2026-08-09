"""Benign Python whose *text* contains `eval(` without any call to eval.

Scope note: this file is scanned by whatever rule pack is loaded, including
third-party community rules. So it holds only constructs that are
unambiguously not eval calls. A method named `eval`, or a `self.eval(x)`
member call, is NOT unambiguous — real rules flag those deliberately. That
distinction is exercised in the matcher's own unit tests instead.
"""

# A comment mentioning eval(user_input) — text, not code.
DOC = "never call eval(x) on untrusted input"
HELP = 'usage: eval(expr)'


def evaluate(expr):          # name merely contains "eval"
    return expr


def retrieval(items):        # "eval" appears mid-word
    return list(items)


evaluated = evaluate("1 + 1")
