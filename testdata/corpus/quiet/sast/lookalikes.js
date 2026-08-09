// Benign JavaScript whose *text* contains `eval(` without any call to eval.
//
// Scope note: this file is scanned by whatever rule pack is loaded, including
// third-party community rules. So it holds only constructs that are
// unambiguously not eval calls. A method literally named `eval`, or a
// `obj.eval(x)` member call, is NOT unambiguous — real rules flag those on
// purpose, because they cannot tell a user-defined `.eval()` from `window.eval`.
// That distinction is exercised in the matcher's own unit tests, where the
// pattern is ours to control.

const DOC = "do not use eval(userInput)";   // string literal
const HELP = 'eval(expr) is unsafe';

function evaluate(expr) {                    // name contains "eval"
  return expr;
}

const retrieval = (xs) => xs;                // "eval" mid-word
const reevaluated = 1;                       // and again

export { evaluate, retrieval, DOC, HELP, reevaluated };
