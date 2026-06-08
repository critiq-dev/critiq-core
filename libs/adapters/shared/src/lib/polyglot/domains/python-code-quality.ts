import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';

export const PYTHON_CODE_QUALITY_FACT_KINDS = {
  fileOpenWithoutContextManager: 'python.correctness.file-open-without-context-manager',
  uselessObjectInspection: 'python.correctness.useless-object-inspection',
  undefinedLoopVariable: 'python.correctness.undefined-loop-variable',
  redefinedOuterName: 'python.correctness.redefined-outer-name',
  invalidEnvvarDefault: 'python.correctness.invalid-envvar-default',
  misplacedBareReturn: 'python.correctness.misplaced-bare-return',
  unreachableCode: 'python.correctness.unreachable-code',
  redundantParentheses: 'python.correctness.redundant-parentheses',
  comparisonWithItself: 'python.correctness.comparison-with-itself',
  expressionNotAssigned: 'python.correctness.expression-not-assigned',
  uselessElseOnLoop: 'python.correctness.useless-else-on-loop',
  starArgsConfusion: 'python.correctness.star-args-confusion',
  undefinedVariable: 'python.correctness.undefined-variable',
  nonIteratorReturned: 'python.correctness.non-iterator-returned',
  cellVarFromLoop: 'python.correctness.cell-var-from-loop',
  redefinedBuiltin: 'python.correctness.redefined-builtin',
  globalVariableUndefined: 'python.correctness.global-variable-undefined',
  globalStatement: 'python.correctness.global-statement',
  selfClsAssignment: 'python.correctness.self-cls-assignment',
  uselessReturn: 'python.correctness.useless-return',
  superWithArguments: 'python.correctness.super-with-arguments',
  unnecessaryComprehension: 'python.correctness.unnecessary-comprehension',
  dictItemsIteration: 'python.correctness.dict-items-iteration',
} as const;

export interface CollectPythonCodeQualityFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectPythonCodeQualityFacts(
  options: CollectPythonCodeQualityFactsOptions,
): ObservedFact[] {
  const { text, detector, path } = options;

  return [
    ...collectFileOpenWithoutContextManagerFacts(text, detector),
    ...collectUselessObjectInspectionFacts(text, detector),
    ...collectUndefinedLoopVariableFacts(text, detector),
    ...collectRedefinedOuterNameFacts(text, detector),
    ...collectInvalidEnvvarDefaultFacts(text, detector),
    ...collectMisplacedBareReturnFacts(text, detector),
    ...collectUnreachableCodeFacts(text, detector),
    ...collectRedundantParenthesesFacts(text, detector),
    ...collectComparisonWithItselfFacts(text, detector),
    ...collectExpressionNotAssignedFacts(text, detector),
    ...collectUselessElseOnLoopFacts(text, detector),
    ...collectStarArgsConfusionFacts(text, detector),
    ...collectUndefinedVariableFacts(text, detector),
    ...collectNonIteratorReturnedFacts(text, detector),
    ...collectCellVarFromLoopFacts(text, detector),
    ...collectRedefinedBuiltinFacts(text, detector),
    ...collectGlobalVariableUndefinedFacts(text, detector),
    ...collectGlobalStatementFacts(text, detector),
    ...collectSelfClsAssignmentFacts(text, detector),
    ...collectUselessReturnFacts(text, detector),
    ...collectSuperWithArgumentsFacts(text, detector),
    ...collectUnnecessaryComprehensionFacts(text, detector),
    ...collectDictItemsIterationFacts(text, detector),
  ];
}

function collectFileOpenWithoutContextManagerFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.fileOpenWithoutContextManager,
    appliesTo: 'block',
    pattern: /^\s*(?!(?:with|#))\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*open\s*\(/gm,
  });
}

function collectUselessObjectInspectionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.uselessObjectInspection,
    appliesTo: 'block',
    pattern: /\b(?:list|set|dict|tuple)\s*\(\s*(?:\[[^\]]*for\s|[({][^)}]*for\s)/g,
  });
}

function collectUndefinedLoopVariableFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.undefinedLoopVariable,
    appliesTo: 'block',
    pattern: /^\s*for\s+(\w+)\s+in[\s\S]*?\n[\s\S]*?\s*print\s*\(\s*\1\s*\)/gm,
  });
}

function collectRedefinedOuterNameFacts(
  _text: string,
  _detector: string,
): ObservedFact[] {
  // Requires scope analysis; skip for now
  return [];
}

function collectInvalidEnvvarDefaultFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.invalidEnvvarDefault,
    appliesTo: 'block',
    pattern: /\bos\.getenv\s*\(\s*['"][^'"]+['"],\s*['"](?:True|False)['"]\s*\)/g,
  });
}

function collectMisplacedBareReturnFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.misplacedBareReturn,
    appliesTo: 'block',
    pattern: /^\s+if\s+[^:]+:\s*\n\s+return\s*$/gm,
  });
}

function collectUnreachableCodeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.unreachableCode,
    appliesTo: 'block',
    pattern: /\breturn\s+[^\n]+\n\s*\S/g,
  });
}

function collectRedundantParenthesesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.redundantParentheses,
    appliesTo: 'block',
    pattern: /^\s*[A-Za-z_]\w*\s*=\s*\(\s*[A-Za-z_]\w*\s*[+\-*/]\s*[A-Za-z_]\w*\s*\)\s*$/gm,
  });
}

function collectComparisonWithItselfFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.comparisonWithItself,
    appliesTo: 'block',
    pattern: /\b([A-Za-z_]\w*)\s*(?:==|!=|is|is\s+not)\s*\1\b/g,
    predicate: (match) => !match.matchedText.includes('__'),
  });
}

function collectExpressionNotAssignedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.expressionNotAssigned,
    appliesTo: 'block',
    pattern: /^\s+[A-Za-z_]\w*\s*[+\-*/]\s*[A-Za-z_]\w*\s*$/gm,
  });
}

function collectUselessElseOnLoopFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.uselessElseOnLoop,
    appliesTo: 'block',
    pattern: /^\s*(?:for|while)\b[\s\S]*?\n[\s\S]*?\bbreak\b[\s\S]*?\n\s*else\s*:/gm,
  });
}

function collectStarArgsConfusionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.starArgsConfusion,
    appliesTo: 'block',
    pattern: /def\s+\w+\s*\(\s*\*args\s*,\s*\*kwargs/g,
  });
}

function collectUndefinedVariableFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.undefinedVariable,
    appliesTo: 'block',
    pattern: /if\s+[^:]+:\s*\n\s+(\w+)\s*=[^\n]+\n[\s\S]*?\s*return\s+\1\b/gm,
  });
}

function collectNonIteratorReturnedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.nonIteratorReturned,
    appliesTo: 'block',
    pattern: /^\s*def\s+\w+\([^)]*\)\s*:\s*\n\s+return\s+None\s*\n\s*for\s+\w+\s+in\s+\w+\(/gm,
  });
}

function collectCellVarFromLoopFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.cellVarFromLoop,
    appliesTo: 'block',
    pattern: /\bfor\s+(\w+)\s+in[\s\S]{0,200}lambda\s*:\s*\1\b/g,
  });
}

function collectRedefinedBuiltinFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.redefinedBuiltin,
    appliesTo: 'block',
    pattern: /^\s*def\s+(?:list|dict|set|str|int|float|bool|tuple|type|id|sum|max|min|len|map|filter|zip|range|print|open|input)\s*\(/gm,
  });
}

function collectGlobalVariableUndefinedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.globalVariableUndefined,
    appliesTo: 'block',
    pattern: /^\s*global\s+(\w+)\s*$/gm,
  });
}

function collectGlobalStatementFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.globalStatement,
    appliesTo: 'block',
    pattern: /^\s*global\s+\w+/gm,
  });
}

function collectSelfClsAssignmentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.selfClsAssignment,
    appliesTo: 'block',
    pattern: /^\s+(?:self|cls)\s*=/gm,
  });
}

function collectUselessReturnFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.uselessReturn,
    appliesTo: 'block',
    pattern: /^\s+return\s*$/gm,
  });
}

function collectSuperWithArgumentsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.superWithArguments,
    appliesTo: 'block',
    pattern: /\bsuper\s*\(\s*\w+\s*,\s*self\s*\)/g,
  });
}

function collectUnnecessaryComprehensionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.unnecessaryComprehension,
    appliesTo: 'block',
    pattern: /\b(?:list|set)\s*\(\s*\[[^\]]*for\s[^\]]*\]\s*\)/g,
  });
}

function collectDictItemsIterationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CODE_QUALITY_FACT_KINDS.dictItemsIteration,
    appliesTo: 'block',
    pattern: /\bfor\s+(\w+)\s+in\s+(\w+)\s*:\s*\n\s+\2\s*\[\s*\1\s*\]/g,
  });
}
