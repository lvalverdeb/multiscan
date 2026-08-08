"""Benign Python that a *textual* eval-matcher would flag and a structural one
must not. Every construct here contains the letters `eval` without being a
call to the builtin."""

# A comment mentioning eval(user_input) — text, not code.
DOC = "never call eval(x) on untrusted input"        # a string literal, not a call
HELP = 'usage: eval(expr)'

def evaluate(expr):                                   # name merely contains "eval"
    return expr


class Evaluator:
    def eval(self, expr):                             # a METHOD named eval
        return expr

    def run(self, expr):
        return self.eval(expr)                        # attribute call, not bare eval


def retrieval(items):                                 # "eval" appears mid-word
    return list(items)


evaluated = evaluate("1 + 1")
result = Evaluator().eval("1 + 1")
