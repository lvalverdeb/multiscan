// Benign JavaScript whose text contains `eval(` in several places without any
// call to the global eval.
const DOC = "do not use eval(userInput)";   // string literal
const HELP = 'eval(expr) is unsafe';

function evaluate(expr) {                    // name contains "eval"
  return expr;
}

class Evaluator {
  eval(expr) {                               // a method named eval
    return expr;
  }
  run(expr) {
    return this.eval(expr);                  // member call, not the global
  }
}

const retrieval = (xs) => xs;                // "eval" mid-word
export { evaluate, Evaluator, retrieval, DOC, HELP };
