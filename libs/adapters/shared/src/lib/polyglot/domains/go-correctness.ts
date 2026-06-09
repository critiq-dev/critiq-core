import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches, findMatchingDelimiter } from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const GO_CORRECTNESS_FACT_KINDS = {
  nilMapAssignment: 'go.correctness.nil-map-assignment',
  deferCloseBeforeCheck: 'go.correctness.defer-close-before-check',
  nilContextPassed: 'go.correctness.nil-context-passed',
  timeTickLeak: 'go.correctness.time-tick-leak',
  waitgroupAddInGoroutine: 'go.correctness.waitgroup-add-in-goroutine',
  unusedAppendResult: 'go.correctness.unused-append-result',
  unnecessaryDereference: 'go.correctness.unnecessary-dereference',
  deferInLoop: 'go.correctness.defer-in-loop',
  unreachableSwitchCase: 'go.correctness.unreachable-switch-case',
  duplicateFunctionArguments: 'go.correctness.duplicate-function-arguments',
  duplicateBranchBody: 'go.correctness.duplicate-branch-body',
  duplicateSwitchCases: 'go.correctness.duplicate-switch-cases',
  identicalBinaryOperands: 'go.correctness.identical-binary-operands',
  flagPointerImmediateDeref: 'go.correctness.flag-pointer-immediate-deref',
  terminalCallWithDefer: 'go.correctness.terminal-call-with-defer',
  nilErrorReturned: 'go.correctness.nil-error-returned',
  offByOneIndex: 'go.correctness.off-by-one-index',
  incompleteNilCheck: 'go.correctness.incomplete-nil-check',
  booleanSimplification: 'go.correctness.boolean-simplification',
  suspiciousRegexPattern: 'go.correctness.suspicious-regex-pattern',
  integerTruncation: 'go.correctness.integer-truncation',
  deferredFuncLiteral: 'go.correctness.deferred-func-literal',
  redundantTypeDeclaration: 'go.correctness.redundant-type-declaration',

  interfaceAnyPreferred: 'go.correctness.interface-any-preferred',
  unnecessaryElseReturn: 'go.correctness.unnecessary-else-return',
  bareReturn: 'go.correctness.bare-return',
  booleanLiteralInExpression: 'go.correctness.boolean-literal-in-expression',
  unexportedCapitalName: 'go.correctness.unexported-capital-name',
  httpNobodyNil: 'go.correctness.http-nobody-nil',
  stringConcatSimplify: 'go.correctness.string-concat-simplify',
  impossibleInterfaceNilCheck:
    'go.correctness.impossible-interface-nil-check',
  duplicateIfElseCondition:
    'go.correctness.duplicate-if-else-condition',
} as const;

export interface CollectGoCorrectnessFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectGoCorrectnessFacts(
  options: CollectGoCorrectnessFactsOptions,
): ObservedFact[] {
  const { text, detector, path } = options;

  if (path && isGoCorrectnessSuppressedPath(path)) {
    return [];
  }

  return dedupeFacts([
    ...collectNilMapAssignmentFacts(text, detector),
    ...collectDeferCloseBeforeCheckFacts(text, detector),
    ...collectNilContextPassedFacts(text, detector),
    ...collectTimeTickLeakFacts(text, detector),
    ...collectWaitgroupAddInGoroutineFacts(text, detector),
    ...collectUnusedAppendResultFacts(text, detector),
    ...collectDeferInLoopFacts(text, detector),
    ...collectUnreachableSwitchCaseFacts(text, detector),
    ...collectUnnecessaryDereferenceFacts(text, detector),
    ...collectDuplicateFunctionArgumentsFacts(text, detector),
    ...collectDuplicateBranchBodyFacts(text, detector),
    ...collectDuplicateSwitchCasesFacts(text, detector),
    ...collectIdenticalBinaryOperandsFacts(text, detector),
    ...collectFlagPointerImmediateDerefFacts(text, detector),
    ...collectTerminalCallWithDeferFacts(text, detector),
    ...collectNilErrorReturnedFacts(text, detector),
    ...collectOffByOneIndexFacts(text, detector),
    ...collectIncompleteNilCheckFacts(text, detector),
    ...collectBooleanSimplificationFacts(text, detector),
    ...collectSuspiciousRegexPatternFacts(text, detector),
    ...collectIntegerTruncationFacts(text, detector),
    ...collectDeferredFuncLiteralFacts(text, detector),
    ...collectRedundantTypeDeclarationFacts(text, detector),
    ...collectInterfaceAnyPreferredFacts(text, detector),
    ...collectUnnecessaryElseReturnFacts(text, detector),
    ...collectBareReturnFacts(text, detector),
    ...collectBooleanLiteralInExpressionFacts(text, detector),
    ...collectUnexportedCapitalNameFacts(text, detector),
    ...collectHttpNobodyNilFacts(text, detector),
    ...collectStringConcatSimplifyFacts(text, detector),
    ...collectImpossibleInterfaceNilCheckFacts(text, detector),
    ...collectDuplicateIfElseConditionFacts(text, detector),
  ]);
}

function isGoCorrectnessSuppressedPath(path: string): boolean {
  return (
    /(^|\/)testdata(\/|$)/u.test(path) ||
    /_test\.go$/u.test(path) ||
    /(^|\/)vendor(\/|$)/u.test(path)
  );
}

/**
 * Flags `var m map[...]T` declarations whose name is later written to with
 * `m[key] = value` without an intervening `make(map[...])` or composite literal
 * assignment. The nil map write would panic at runtime.
 */
function collectNilMapAssignmentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.nilMapAssignment;
  const findings: ObservedFact[] = [];

  const declarationPattern =
    /\bvar\s+([A-Za-z_][A-Za-z0-9_]*)\s+map\[[^\]\n]+\][A-Za-z_][A-Za-z0-9_.[\]*]*\s*$/gmu;

  for (const declMatch of findAllMatches(text, declarationPattern)) {
    const name = extractMapName(declMatch.matchedText);

    if (!name) {
      continue;
    }

    const afterDecl = text.slice(declMatch.endOffset);

    const reinitPattern = new RegExp(
      `(?<![A-Za-z_0-9])${escapeRegex(name)}\\s*(?:=|:=)\\s*(?:make\\s*\\(|map\\[)`,
      'u',
    );

    if (reinitPattern.test(afterDecl)) {
      continue;
    }

    const writePattern = new RegExp(
      `(?<![A-Za-z_0-9])${escapeRegex(name)}\\s*\\[[^\\]\\n]+\\]\\s*=(?!=)`,
      'gu',
    );

    for (const writeMatch of findAllMatches(afterDecl, writePattern)) {
      const absoluteStart = declMatch.endOffset + writeMatch.startOffset;
      const absoluteEnd = declMatch.endOffset + writeMatch.endOffset;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteEnd,
          text: writeMatch.matchedText,
        }),
      );
    }
  }

  return findings;
}

function extractMapName(declarationText: string): string | undefined {
  const match = /\bvar\s+([A-Za-z_][A-Za-z0-9_]*)\s+map\[/u.exec(
    declarationText,
  );

  return match?.[1];
}

/**
 * Flags `defer resource.Close()` calls that appear before an `if err != nil`
 * check on the immediately preceding open-style call. Closing the resource
 * before validating `err` can panic when the open call returned a nil handle.
 */
function collectDeferCloseBeforeCheckFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.deferCloseBeforeCheck;
  const findings: ObservedFact[] = [];

  const pattern =
    /([A-Za-z_][A-Za-z0-9_]*)\s*,\s*err\s*:?=\s*[^\n]*\b(?:Open|Create|OpenFile|Dial|DialContext|NewRequest|NewRequestWithContext|Get|Post|Do)\s*\([^\n]*\)\s*\r?\n\s*defer\s+\1(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.Close\s*\(\s*\)\s*\r?\n\s*if\s+err\s*!=\s*nil/gu;

  for (const match of findAllMatches(text, pattern)) {
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
      }),
    );
  }

  return findings;
}

/**
 * Flags calls where a literal `nil` is passed as the first argument to a
 * function whose name ends in `Context` (or to `context.With*` helpers),
 * where Go convention expects a non-nil `context.Context`.
 */
function collectNilContextPassedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_CORRECTNESS_FACT_KINDS.nilContextPassed,
    appliesTo: 'block',
    pattern:
      /\b(?:context\.With(?:Value|Cancel|Timeout|Deadline)|(?:[A-Za-z_][A-Za-z0-9_]*\.)?[A-Z][A-Za-z0-9_]*Context)\s*\(\s*nil\s*[,)]/gu,
  });
}

/**
 * Flags `time.Tick(...)` usages. `time.Tick` returns a channel that cannot be
 * stopped, leaking the underlying ticker for the lifetime of the program.
 */
function collectTimeTickLeakFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_CORRECTNESS_FACT_KINDS.timeTickLeak,
    appliesTo: 'block',
    pattern: /\btime\.Tick\s*\(/gu,
  });
}

/**
 * Flags `wg.Add(...)` calls that appear inside the body of a `go func() { ... }`
 * literal, where `wg` is a known `sync.WaitGroup` variable. `Add` must run on
 * the launching goroutine to avoid racing with `Wait`.
 */
function collectWaitgroupAddInGoroutineFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.waitgroupAddInGoroutine;
  const findings: ObservedFact[] = [];

  const waitGroupNames = collectWaitGroupNames(text);

  if (waitGroupNames.size === 0) {
    return findings;
  }

  const goFuncPattern = /\bgo\s+func\s*\(/gu;

  for (const match of findAllMatches(text, goFuncPattern)) {
    const openBraceIndex = findGoroutineOpenBrace(text, match.endOffset);

    if (openBraceIndex < 0) {
      continue;
    }

    const closeBraceIndex = findMatchingDelimiter(
      text,
      openBraceIndex,
      '{',
      '}',
    );

    if (closeBraceIndex < 0) {
      continue;
    }

    const inner = text.slice(openBraceIndex + 1, closeBraceIndex);

    for (const name of waitGroupNames) {
      const addPattern = new RegExp(
        `(?<![A-Za-z_0-9])${escapeRegex(name)}\\.Add\\s*\\(`,
        'gu',
      );

      for (const innerMatch of inner.matchAll(addPattern)) {
        const innerStart = innerMatch.index ?? 0;
        const absoluteStart = openBraceIndex + 1 + innerStart;
        const absoluteEnd = absoluteStart + innerMatch[0].length;

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteEnd,
            text: innerMatch[0],
          }),
        );
      }
    }
  }

  return findings;
}

function findGoroutineOpenBrace(text: string, fromOffset: number): number {
  let depth = 0;

  for (let index = fromOffset - 1; index < text.length; index += 1) {
    const char = text[index];

    if (char === '(') {
      depth += 1;
      continue;
    }

    if (char === ')') {
      depth -= 1;
      continue;
    }

    if (char === '{' && depth === 0) {
      return index;
    }

    if (char === '\n' && depth === 0) {
      return -1;
    }
  }

  return -1;
}

function collectWaitGroupNames(text: string): Set<string> {
  const names = new Set<string>();

  const typedPattern =
    /\b(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+(?:\*\s*)?sync\.WaitGroup\b/gu;
  for (const match of text.matchAll(typedPattern)) {
    names.add(match[1]);
  }

  const literalPattern =
    /\b([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*(?:&\s*)?sync\.WaitGroup\s*\{\s*\}/gu;
  for (const match of text.matchAll(literalPattern)) {
    names.add(match[1]);
  }

  return names;
}

/**
 * Flags `append(slice, ...)` calls that appear as a standalone statement (the
 * result of `append` is dropped). The return value of `append` must always be
 * assigned back to the slice.
 */
function collectUnusedAppendResultFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_CORRECTNESS_FACT_KINDS.unusedAppendResult,
    appliesTo: 'block',
    pattern: /^[ \t]*append\s*\(/gmu,
  });
}

/**
 * Flags `defer` statements that appear inside the body of a `for` or `for ... range`
 * loop. Defers stack until the surrounding function returns, so deferring inside
 * loops postpones cleanup until well after the iteration is over.
 */
function collectDeferInLoopFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.deferInLoop;
  const findings: ObservedFact[] = [];

  const loopHeaderPattern = /\bfor\b[^\n{]*\{/gu;

  for (const match of findAllMatches(text, loopHeaderPattern)) {
    const openBraceIndex = match.endOffset - 1;

    if (text[openBraceIndex] !== '{') {
      continue;
    }

    const closeBraceIndex = findMatchingDelimiter(
      text,
      openBraceIndex,
      '{',
      '}',
    );

    if (closeBraceIndex < 0) {
      continue;
    }

    const inner = text.slice(openBraceIndex + 1, closeBraceIndex);
    const cleaned = stripNestedFunctionBodies(inner);
    const deferPattern = /\bdefer\b/gu;

    for (const innerMatch of cleaned.matchAll(deferPattern)) {
      const innerStart = innerMatch.index ?? 0;
      const absoluteStart = openBraceIndex + 1 + innerStart;
      const absoluteEnd = absoluteStart + innerMatch[0].length;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteEnd,
          text: innerMatch[0],
        }),
      );
    }
  }

  return findings;
}

/**
 * Flags cases after an unconditional exit (return/break/continue/panic/os.Exit/log.Fatal)
 * in the preceding case body without a `fallthrough` keyword.
 */
function collectUnreachableSwitchCaseFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.unreachableSwitchCase;
  const findings: ObservedFact[] = [];

  const switchPattern = /\bswitch\s[^{]*\{/gu;

  for (const match of findAllMatches(text, switchPattern)) {
    const openBraceIndex = match.endOffset - 1;
    const closeBraceIndex = findMatchingDelimiter(text, openBraceIndex, '{', '}');

    if (closeBraceIndex < 0) {
      continue;
    }

    const body = text.slice(openBraceIndex + 1, closeBraceIndex);
    const caseLabels = collectCaseLabelOffsets(body);

    for (let i = 1; i < caseLabels.length; i += 1) {
      const prevStart = caseLabels[i - 1].offset;
      const prevBody = body.slice(prevStart, caseLabels[i].offset);

      const cleanPrevBody = stripNestedFunctionBodies(prevBody);
      const cleanPrevBodyNoStrings = removeStringLiterals(cleanPrevBody);

      const hasFallthrough = /\bfallthrough\b/u.test(cleanPrevBodyNoStrings);
      const hasUnconditionalExit = /\b(?:return|break|continue|panic\b|os\.Exit\s*\(|log\.Fatal)/u.test(cleanPrevBodyNoStrings);

      if (hasUnconditionalExit && !hasFallthrough) {
        const absoluteStart = openBraceIndex + 1 + caseLabels[i].offset;
        const absoluteEnd = openBraceIndex + 1 + caseLabels[i].offset + caseLabels[i].label.length;

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteEnd,
            text: caseLabels[i].label,
          }),
        );
      }
    }
  }

  return findings;
}

/**
 * Flags redundant pointer dereference expressions where Go auto-dereferences
 * pointers for field access (`(*ptr).field` → `ptr.field`) and indexing
 * (`(*ptr)[index]` → `ptr[index]`).
 */
function collectUnnecessaryDereferenceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.unnecessaryDereference;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const singleDerefDot = /\(\*\s*([A-Za-z_][A-Za-z0-9_.]*)\)\s*\./gu;
  const doubleDerefDot = /\(\*\*\s*([A-Za-z_][A-Za-z0-9_.]*)\)\s*\./gu;
  const singleDerefBracket = /\(\*\s*([A-Za-z_][A-Za-z0-9_.]*)\)\s*\[/gu;

  for (const match of findAllMatches(cleanedText, singleDerefDot)) {
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: text.slice(match.startOffset, match.endOffset),
      }),
    );
  }

  for (const match of findAllMatches(cleanedText, doubleDerefDot)) {
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: text.slice(match.startOffset, match.endOffset),
      }),
    );
  }

  for (const match of findAllMatches(cleanedText, singleDerefBracket)) {
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: text.slice(match.startOffset, match.endOffset),
      }),
    );
  }

  return findings;
}

interface CaseLabelOffset {
  offset: number;
  label: string;
}

function collectCaseLabelOffsets(body: string): CaseLabelOffset[] {
  const labels: CaseLabelOffset[] = [];

  const casePattern = /(?:\bcase\b[^:]*:|^\s*default:)/gmu;

  for (const m of findAllMatches(body, casePattern)) {
    const textBefore = body.slice(0, m.startOffset);
    const openCount = (textBefore.match(/\{/gu) ?? []).length;
    const closeCount = (textBefore.match(/\}/gu) ?? []).length;

    if (openCount === closeCount) {
      labels.push({ offset: m.startOffset, label: m.matchedText.trim() });
    }
  }

  return labels;
}

function removeStringLiterals(text: string): string {
  return text.replace(/"([^"\\]*(?:\\.[^"\\]*)*)"/gu, '""').replace(/`([^`]*)`/gu, '``');
}

/**
 * Flags consecutive identical identifier tokens in function call argument lists.
 */
function collectDuplicateFunctionArgumentsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.duplicateFunctionArguments;
  const findings: ObservedFact[] = [];

  const callPattern = /[A-Za-z_][A-Za-z0-9_]*\s*\(([^()]*)\)/gu;

  for (const match of findAllMatches(text, callPattern)) {
    const argsText = match.matchedText;
    const start = argsText.indexOf('(');

    if (start < 0) {
      continue;
    }

    const args = argsText.slice(start + 1, -1).trim();

    if (!args) {
      continue;
    }

    const argList = splitArgsRespectingQuotes(args);

    for (let i = 1; i < argList.length; i += 1) {
      const prev = argList[i - 1].value.trim();
      const curr = argList[i].value.trim();

      if (
        prev &&
        curr &&
        prev === curr &&
        /^[A-Za-z_][A-Za-z0-9_]*$/u.test(prev)
      ) {
        const argListStart = match.startOffset + start + 1;

        const prevIndex = args.indexOf(prev);
        const currIndex = args.indexOf(curr, prevIndex + prev.length);

        if (prevIndex < 0 || currIndex < 0) {
          continue;
        }

        const absoluteStart = argListStart + prevIndex;
        const absoluteEnd = argListStart + currIndex + curr.length;

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteEnd,
            text: `${prev}, ${curr}`,
          }),
        );
      }
    }
  }

  return findings;
}

interface ArgWithOffset {
  value: string;
  startOffset: number;
}

function splitArgsRespectingQuotes(args: string): ArgWithOffset[] {
  const result: ArgWithOffset[] = [];
  let current = '';
  let currentStart = 0;
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  let inBacktick = false;
  let pos = 0;

  for (const char of args) {
    if (char === '\'' && !inDouble && !inBacktick) {
      inSingle = !inSingle;
      current += char;
    } else if (char === '"' && !inSingle && !inBacktick) {
      inDouble = !inDouble;
      current += char;
    } else if (char === '`' && !inSingle && !inDouble) {
      inBacktick = !inBacktick;
      current += char;
    } else if (char === '(' && !inSingle && !inDouble && !inBacktick) {
      depth += 1;
      current += char;
    } else if (char === ')' && !inSingle && !inDouble && !inBacktick) {
      depth -= 1;
      current += char;
    } else if (char === ',' && depth === 0 && !inSingle && !inDouble && !inBacktick) {
      result.push({ value: current.trim(), startOffset: currentStart });
      current = '';
      currentStart = pos + 1;
    } else {
      if (!current && currentStart === 0) {
        currentStart = pos;
      }
      current += char;
    }
    pos += 1;
  }

  if (current.trim()) {
    result.push({ value: current.trim(), startOffset: currentStart });
  }

  return result;
}

/**
 * Flags adjacent if-else branches with identical single-line bodies.
 * Best-effort — limited to single-line bodies only.
 */
function collectDuplicateBranchBodyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.duplicateBranchBody;
  const findings: ObservedFact[] = [];

  const elsePattern = /\belse\s*(?:\{|if\s+[^{]+\{)/gu;
  const elseMatches = Array.from(text.matchAll(elsePattern));

  for (const m of elseMatches) {
    const elseStart = m.index ?? 0;
    const bodyStart = text.indexOf('{', elseStart);
    const bodyEnd = text.indexOf('}', bodyStart);

    if (bodyStart < 0 || bodyEnd < 0) {
      continue;
    }

    const body = text.slice(bodyStart + 1, bodyEnd);

    if (body.includes('\n')) {
      continue;
    }

    const bodyText = body.trim();

    if (!bodyText) {
      continue;
    }

    const prevCloseBrace = text.lastIndexOf('}', elseStart - 1);

    if (prevCloseBrace < 0) {
      continue;
    }

    const prevOpenBrace = text.lastIndexOf('{', prevCloseBrace);

    if (prevOpenBrace < 0) {
      continue;
    }

    const prevBody = text.slice(prevOpenBrace + 1, prevCloseBrace);

    if (prevBody.includes('\n')) {
      continue;
    }

    const prevBodyText = prevBody.trim();

    if (prevBodyText && prevBodyText === bodyText) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: elseStart,
          endOffset: bodyEnd + 1,
          text: text.slice(elseStart, bodyEnd + 1),
        }),
      );
    }
  }

  return findings;
}

/**
 * Flags duplicate literal case values in switch statements.
 */
function collectDuplicateSwitchCasesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.duplicateSwitchCases;
  const findings: ObservedFact[] = [];

  const switchPattern = /\bswitch\s[^{]*\{/gu;

  for (const match of findAllMatches(text, switchPattern)) {
    const openBraceIndex = match.endOffset - 1;
    const closeBraceIndex = findMatchingDelimiter(text, openBraceIndex, '{', '}');

    if (closeBraceIndex < 0) {
      continue;
    }

    const body = text.slice(openBraceIndex + 1, closeBraceIndex);
    const seenCaseValues = new Map<string, number>();

    const caseValuePattern = /\bcase\s+((?:"[^"]*"|[0-9]+|[A-Z_a-z][A-Za-z0-9_]*)(?:\s*,\s*(?:"[^"]*"|[0-9]+|[A-Z_a-z][A-Za-z0-9_]*))*)\s*:/gu;

    for (const cv of findAllMatches(body, caseValuePattern)) {
      const valuesText = cv.matchedText.replace(/^case\s+/u, '').replace(/\s*:\s*$/u, '');
      const values = valuesText.split(',').map((v) => v.trim());

      for (const val of values) {
        if (seenCaseValues.has(val)) {
          const absoluteStart = openBraceIndex + 1 + cv.startOffset;
          const absoluteEnd = openBraceIndex + 1 + cv.endOffset;

          findings.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: absoluteStart,
              endOffset: absoluteEnd,
              text: `case ${val}`,
            }),
          );
        } else {
          seenCaseValues.set(val, cv.startOffset);
        }
      }
    }
  }

  return findings;
}

/**
 * Flags binary operations where LHS and RHS are textually identical
 * non-function-call expressions.
 */
function collectIdenticalBinaryOperandsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.identicalBinaryOperands;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const binaryOps =
    /(?:\b|(?<=\s))(true|false|[A-Za-z_][A-Za-z0-9_.]*|"[^"]*"|[0-9]+(?:\.[0-9]+)?)\s*(==|!=|<=|>=|&&|\|\||<<|>>|[+\-*/%&|^<>])\s*(true|false|[A-Za-z_][A-Za-z0-9_.]*|"[^"]*"|[0-9]+(?:\.[0-9]+)?)(?:\b|(?=\s))/gu;

  const matches = Array.from(cleanedText.matchAll(binaryOps));

  for (const match of matches) {
    const lhs = match[1].trim();
    const op = match[2];
    const rhs = match[3].trim();

    if (!lhs || !op || !rhs) {
      continue;
    }

    if (lhs.includes('(') || rhs.includes('(')) {
      continue;
    }

    if (lhs === rhs) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.index,
          endOffset: match.index + match[0].length,
          text: text.slice(match.index, match.index + match[0].length),
        }),
      );
    }
  }

  return findings;
}

/**
 * Replace the contents of Go string literals (double-quoted and backtick-quoted)
 * with spaces while preserving string boundaries, newlines, and original text length.
 * This prevents false-positive binary-operator matches inside import paths and string content.
 * Offsets remain valid for the original text since length and newlines are preserved.
 */
function replaceStringContents(source: string): string {
  return source.replace(/"([^"\\]*(?:\\.[^"\\]*)*)"/gu, (match) =>
    match[0] + match.slice(1, -1).replace(/[^\n]/gu, ' ') + '"',
  ).replace(/`[^`]*`/gu, (match) =>
    '`' + match.slice(1, -1).replace(/[^\n]/gu, ' ') + '`',
  );
}

/**
 * Flags immediate dereference of flag pointers: `*flag.String(...)`, `*flag.Int(...)`, etc.
 */
function collectFlagPointerImmediateDerefFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_CORRECTNESS_FACT_KINDS.flagPointerImmediateDeref,
    appliesTo: 'block',
    pattern: /\*flag\.(?:Bool|Int|Int64|Uint|Uint64|Float64|String|Duration|Func|Var)\s*\(/gu,
  });
}

/**
 * Flags functions that contain both `defer` statements and terminal calls
 * (`os.Exit`, `log.Fatal`, `log.Fatalf`, `log.Fatalln`).
 */
function collectTerminalCallWithDeferFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.terminalCallWithDefer;
  const findings: ObservedFact[] = [];

  const funcPattern = /\bfunc\b[^{]*\{/gu;

  for (const match of findAllMatches(text, funcPattern)) {
    const openBraceIndex = match.endOffset - 1;

    if (text[openBraceIndex] !== '{') {
      continue;
    }

    const closeBraceIndex = findMatchingDelimiter(text, openBraceIndex, '{', '}');

    if (closeBraceIndex < 0) {
      continue;
    }

    const body = text.slice(openBraceIndex + 1, closeBraceIndex);
    const cleanBody = stripNestedFunctionBodies(body);

    const hasDefer = /\bdefer\b/u.test(cleanBody);
    const hasTerminalCall = /\b(?:os\.Exit|log\.Fatal[fln]?)\s*\(/u.test(cleanBody);

    if (hasDefer && hasTerminalCall) {
      const terminalPattern = /\b(?:os\.Exit|log\.Fatal[fln]?)\s*\(/gu;

      for (const inner of findAllMatches(cleanBody, terminalPattern)) {
        const absoluteStart = openBraceIndex + 1 + inner.startOffset;
        const absoluteEnd = openBraceIndex + 1 + inner.endOffset;

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteEnd,
            text: inner.matchedText,
          }),
        );
      }
    }
  }

  return findings;
}

/**
 * Flags `return nil, nil` patterns where a nil value is returned with a nil error.
 * Best-effort — limited to the explicit `return nil, nil` pattern.
 */
function collectNilErrorReturnedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_CORRECTNESS_FACT_KINDS.nilErrorReturned,
    appliesTo: 'block',
    pattern: /\breturn\s+nil\s*,\s*nil\b/gu,
  });
}

/**
 * Replace the bodies of nested function literals with spaces so a `defer`
 * keyword that belongs to an inner closure does not get attributed to the
 * surrounding loop body. Offsets and newlines are preserved.
 */
function stripNestedFunctionBodies(source: string): string {
  const chars = source.split('');
  const funcPattern = /\bfunc\s*\(/gu;

  for (const match of source.matchAll(funcPattern)) {
    const matchStart = match.index ?? 0;
    const openBrace = findFunctionOpenBrace(source, matchStart);

    if (openBrace < 0) {
      continue;
    }

    let depth = 0;
    let closeBrace = -1;

    for (let index = openBrace; index < source.length; index += 1) {
      const char = source[index];

      if (char === '{') {
        depth += 1;
        continue;
      }

      if (char === '}') {
        depth -= 1;

        if (depth === 0) {
          closeBrace = index;
          break;
        }
      }
    }

    if (closeBrace < 0) {
      continue;
    }

    for (let index = openBrace + 1; index < closeBrace; index += 1) {
      if (chars[index] !== '\n') {
        chars[index] = ' ';
      }
    }
  }

  return chars.join('');
}

function findFunctionOpenBrace(source: string, fromOffset: number): number {
  let depth = 0;

  for (let index = fromOffset; index < source.length; index += 1) {
    const char = source[index];

    if (char === '(') {
      depth += 1;
      continue;
    }

    if (char === ')') {
      depth -= 1;
      continue;
    }

    if (char === '{' && depth === 0) {
      return index;
    }
  }

  return -1;
}

/**
 * Flags `arr[len(arr)]` — indexing an array/slice at its own length,
 * which is always one past the last valid index.
 */
function collectOffByOneIndexFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.offByOneIndex;
  const findings: ObservedFact[] = [];

  const pattern = /([A-Za-z_][A-Za-z0-9_]*)\[len\(\1\)\]/gu;

  for (const match of findAllMatches(text, pattern)) {
    if (isIndexNestedInBrackets(text, match.startOffset, match.endOffset)) {
      continue;
    }
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
      }),
    );
  }

  return findings;
}

function isIndexNestedInBrackets(
  text: string,
  startOffset: number,
  _endOffset: number,
): boolean {
  const before = text.slice(0, startOffset);
  let depth = 0;
  for (let i = before.length - 1; i >= 0; i -= 1) {
    const ch = before[i];
    if (ch === ']') {
      depth += 1;
    } else if (ch === '[') {
      depth -= 1;
      if (depth < 0) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Flags `xs != nil && xs[index]` — checking nil but not empty on a slice.
 * A non-nil empty slice would panic.
 */
function collectIncompleteNilCheckFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.incompleteNilCheck;
  const findings: ObservedFact[] = [];

  const pattern = /([A-Za-z_][A-Za-z0-9_]*)\s*!=\s*nil\s*&&\s*\1\s*\[/gu;

  for (const match of findAllMatches(text, pattern)) {
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
      }),
    );
  }

  return findings;
}

/**
 * Flags boolean expressions that can be simplified:
 * - `x > y - 1` → `x >= y`
 * - `x < y || x == y` → `x <= y`
 * - `x > y || x == y` → `x >= y`
 * Best-effort regex — moderate false positive rate.
 */
function collectBooleanSimplificationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.booleanSimplification;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const subtractOnePattern =
    /([A-Za-z_][A-Za-z0-9_.]*)\s*>\s*([A-Za-z_][A-Za-z0-9_.]*)\s*-\s*1\b/gu;

  for (const match of findAllMatches(cleanedText, subtractOnePattern)) {
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: text.slice(match.startOffset, match.endOffset),
      }),
    );
  }

  const orEqualPattern =
    /([A-Za-z_][A-Za-z0-9_.]*)\s*(?:<|>)\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\|\|\s*\1\s*==\s*\2/gu;

  for (const match of findAllMatches(cleanedText, orEqualPattern)) {
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: text.slice(match.startOffset, match.endOffset),
      }),
    );
  }

  return findings;
}

/**
 * Flags calls to `regexp.Compile`, `regexp.MustCompile`, `regexp.CompilePOSIX`,
 * `regexp.MustCompilePOSIX` where the regex pattern string literal contains an
 * unescaped dot (`.`). Unescaped dots match any character instead of a literal dot.
 */
function collectSuspiciousRegexPatternFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.suspiciousRegexPattern;
  const findings: ObservedFact[] = [];

  const callPattern =
    /\bregexp\.(?:Must)?Compile(?:POSIX)?\s*\(\s*("[^"]*"|`[^`]*`)/gu;

  for (const match of findAllMatches(text, callPattern)) {
    const arg = match.matchedText;
    const argStart = arg.indexOf('(') + 1;
    const argRaw = arg.slice(argStart).trim();

    const unescapedDotMatch = /(?<!\\)\.(?!\|)(?!\*)(?!\?)(?!\+)(?!\{)(?!\))(?!\])(?!\])(?!\^)(?!\$)/u.exec(
      argRaw,
    );

    if (unescapedDotMatch) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: match.matchedText,
        }),
      );
    }
  }

  return findings;
}

/**
 * Flags potentially lossy integer truncation in comparisons.
 * Detects patterns like `int16(x) < y` where x is truncated before comparison.
 * Best-effort — no type resolution, so false positives are possible.
 */
function collectIntegerTruncationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.integerTruncation;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const narrowPattern =
    /\bint\d{1,2}\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*[<>=!]+\s*([A-Za-z_][A-Za-z0-9_]*)/gu;

  for (const match of findAllMatches(cleanedText, narrowPattern)) {
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: text.slice(match.startOffset, match.endOffset),
      }),
    );
  }

  const reversePattern =
    /([A-Za-z_][A-Za-z0-9_]*)\s*[<>=!]+\s*int\d{1,2}\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/gu;

  for (const match of findAllMatches(cleanedText, reversePattern)) {
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: text.slice(match.startOffset, match.endOffset),
      }),
    );
  }

  return findings;
}

/**
 * Flags `defer func() { bar() }()` patterns that can be simplified to `defer bar()`.
 * The deferred function literal body must contain exactly one expression statement
 * (a function call). Multi-statement bodies, bodies with control flow, function
 * literals that take parameters, and empty bodies are skipped.
 */
function collectDeferredFuncLiteralFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.deferredFuncLiteral;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const deferFuncPattern = /\bdefer\s+func\s*\(\s*\)\s*\{/gu;

  for (const match of findAllMatches(cleanedText, deferFuncPattern)) {
    const openBraceIndex = match.endOffset - 1;

    if (cleanedText[openBraceIndex] !== '{') {
      continue;
    }

    const closeBraceIndex = findMatchingDelimiter(
      cleanedText,
      openBraceIndex,
      '{',
      '}',
    );

    if (closeBraceIndex < 0) {
      continue;
    }

    const body = cleanedText.slice(openBraceIndex + 1, closeBraceIndex);
    const trimmedBody = body.trim();

    if (!trimmedBody) {
      continue;
    }

    const hasControlFlow = /\b(?:if|for|go|select|switch|defer)\b/u.test(trimmedBody);
    if (hasControlFlow) {
      continue;
    }

    const hasMultiStatement = /\n\s*[A-Za-z_]/u.test(trimmedBody) && trimmedBody.includes('\n');
    if (hasMultiStatement) {
      continue;
    }

    const afterClosure = cleanedText.slice(closeBraceIndex + 1);
    const parenCallMatch = /^\s*\(\s*\)/u.exec(afterClosure);
    if (!parenCallMatch) {
      continue;
    }

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: closeBraceIndex + 1 + parenCallMatch[0].length,
        text: text.slice(match.startOffset, closeBraceIndex + 1 + parenCallMatch[0].length),
      }),
    );
  }

  return findings;
}

/**
 * Flags `var foo Type = value` where Type is the same as the RHS literal's type
 * and can be inferred. For example, `var count int = 10` → `var count = 10`.
 *
 * V1 scope: int, string, float32/float64, bool — not int8/16/32/64/uint.
 * Composite type matching (`var s []T = []T{...}`) is also detected.
 */
function collectRedundantTypeDeclarationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.redundantTypeDeclaration;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const baseVarPattern = /\bvar\s+([A-Za-z_][A-Za-z0-9_]*)\s+(int|string|float32|float64|bool)\s*=/gu;

  for (const match of findAllMatches(cleanedText, baseVarPattern)) {
    const varName = match.matchedText.match(/\bvar\s+([A-Za-z_][A-Za-z0-9_]*)/u)?.[1];
    const typeName = match.matchedText.match(/\b(int|string|float32|float64|bool)\b/u)?.[1];
    if (!varName || !typeName) continue;

    const lineAfterEquals = cleanedText.indexOf('\n', match.endOffset);
    const rhsLine = cleanedText.slice(
      match.endOffset,
      lineAfterEquals < 0 ? undefined : lineAfterEquals,
    ).trim();

    if (!rhsLine || rhsLine === 'nil' || rhsLine.endsWith('(')) continue;

    let valueMatch: RegExpMatchArray | null = null;
    switch (typeName) {
      case 'int':
        valueMatch = rhsLine.match(/^-?\d+/u);
        break;
      case 'string':
        valueMatch = rhsLine.match(/^"(?:[^"\\]|\\.)*"/u) || rhsLine.match(/^`[^`]*`/u);
        break;
      case 'float32':
      case 'float64':
        valueMatch = rhsLine.match(/^-?\d+\.?\d*(?:[eE][+-]?\d+)?/u);
        break;
      case 'bool':
        valueMatch = rhsLine.match(/^(?:true|false)/u);
        break;
    }

    if (!valueMatch) continue;

    const afterValue = rhsLine.slice(valueMatch[0].length).trim();
    if (afterValue && !afterValue.startsWith('//')) continue;

    const varTextStart = match.matchedText.search(/\bvar\s+/u);
    if (varTextStart < 0) continue;
    const absoluteStart = match.startOffset + varTextStart;
    const typeEndMatch = /\bvar\s+[A-Za-z_][A-Za-z0-9_]*\s+\w+\s*=/u.exec(
      match.matchedText.slice(varTextStart),
    );
    if (!typeEndMatch) continue;
    const absoluteEnd = match.startOffset + varTextStart + typeEndMatch[0].length;

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: absoluteStart,
        endOffset: absoluteEnd,
        text: text.slice(absoluteStart, absoluteEnd),
      }),
    );
  }

  const compositePattern = /\bvar\s+([A-Za-z_][A-Za-z0-9_]*)\s+(\[?\w+(?:\.\w+)?\]?)\s*=\s*\2\s*\{/gu;

  for (const match of findAllMatches(cleanedText, compositePattern)) {
    const bodyOpenBrace = cleanedText.indexOf('{', match.endOffset - 1);
    if (bodyOpenBrace < 0) continue;

    const bodyCloseBrace = findMatchingDelimiter(cleanedText, bodyOpenBrace, '{', '}');
    if (bodyCloseBrace < 0) continue;

    const afterBody = cleanedText.slice(bodyCloseBrace + 1).trimStart();

    if (afterBody.startsWith(',') || afterBody.startsWith(')')) {
      continue;
    }

    const varDeclEnd = match.matchedText.search(/\bvar\s+/u);
    if (varDeclEnd < 0) continue;
    const varStart = match.startOffset + varDeclEnd;
    const typeMatch = /var\s+[A-Za-z_][A-Za-z0-9_]*\s+\[?\w+(?:\.\w+)?\]?\s*=/u.exec(
      match.matchedText.slice(varDeclEnd),
    );
    if (!typeMatch) continue;

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: varStart,
        endOffset: match.startOffset + varDeclEnd + typeMatch[0].length,
        text: text.slice(varStart, match.startOffset + varDeclEnd + typeMatch[0].length),
      }),
    );
  }

  return findings;
}

/**
 * Flags `interface{}` in type positions (declarations, function signatures,
 * map types, type assertions). Go 1.18+ prefers `any` as a shorter alias.
 */
function collectInterfaceAnyPreferredFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.interfaceAnyPreferred;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const pattern = /\binterface\{\}/gu;

  for (const match of findAllMatches(cleanedText, pattern)) {
    const lineStart = text.lastIndexOf('\n', match.startOffset) + 1;
    const lineBefore = text.slice(
      Math.max(0, lineStart),
      match.startOffset,
    );

    if (/\/\/\s*nolint\b/u.test(lineBefore)) {
      continue;
    }

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
      }),
    );
  }

  return findings;
}

/**
 * Flags `if ... { return/break/continue } else { ... }` patterns where a
 * terminating statement in the if-body makes the else branch unnecessary.
 * Skips else-if chains unless the final else also terminates.
 * Marked experimental due to structural regex parsing limitations.
 */
function collectUnnecessaryElseReturnFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.unnecessaryElseReturn;
  const findings: ObservedFact[] = [];

  const ifPattern = /\bif\s[^{]*\{/gu;

  for (const match of findAllMatches(text, ifPattern)) {
    const openBraceIndex = match.endOffset - 1;

    if (text[openBraceIndex] !== '{') {
      continue;
    }

    const ifBodyClose = findMatchingDelimiter(
      text,
      openBraceIndex,
      '{',
      '}',
    );

    if (ifBodyClose < 0) {
      continue;
    }

    const ifBody = text.slice(openBraceIndex + 1, ifBodyClose);
    const cleanIfBody = stripNestedFunctionBodies(ifBody);
    const lastLine = cleanIfBody.trimEnd().split('\n').pop()?.trim() ?? '';

    const hasTerminatingStmt = /^(?:return|break|continue)\b/u.test(lastLine);

    if (!hasTerminatingStmt) {
      continue;
    }

    const afterIfBody = text.slice(ifBodyClose + 1).trimStart();
    const elseMatch = /^else\s*(?:\{|if\s)/u.exec(afterIfBody);

    if (!elseMatch) {
      continue;
    }

    const elseText = elseMatch[0];

    if (/^else\s+if/u.test(elseText)) {
      const elseIfBody = afterIfBody.slice(elseMatch[0].length - 1);

      if (!elseIfBody.startsWith('{')) {
        continue;
      }

      const elseIfClose = findMatchingDelimiter(
        afterIfBody,
        afterIfBody.indexOf('{'),
        '{',
        '}',
      );

      if (elseIfClose < 0) {
        continue;
      }

      const restAfter = afterIfBody.slice(elseIfClose + 1).trimStart();
      const finalElseMatch = /^else\s*\{/u.exec(restAfter);

      if (!finalElseMatch) {
        continue;
      }

      const finalBodyOpen = restAfter.indexOf('{');
      const finalBodyClose = findMatchingDelimiter(
        restAfter,
        finalBodyOpen,
        '{',
        '}',
      );

      if (finalBodyClose < 0) {
        continue;
      }

      const finalBody = restAfter.slice(finalBodyOpen + 1, finalBodyClose);
      const cleanFinalBody = stripNestedFunctionBodies(finalBody);
      const finalLastLine = cleanFinalBody.trimEnd().split('\n').pop()?.trim() ?? '';

      if (!/^(?:return|break|continue)\b/u.test(finalLastLine)) {
        continue;
      }

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: ifBodyClose + 1 + elseText.length,
          text: text.slice(
            match.startOffset,
            ifBodyClose + 1 + elseText.length,
          ),
        }),
      );
    } else {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: ifBodyClose + 1 + elseMatch[0].length,
          text: text.slice(
            match.startOffset,
            ifBodyClose + 1 + elseMatch[0].length,
          ),
        }),
      );
    }
  }

  return findings;
}

/**
 * Flags bare `return` statements in functions with named return parameters.
 * A bare return returns the current values of named return params, which
 * can be surprising when reading code.
 */
function collectBareReturnFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.bareReturn;
  const findings: ObservedFact[] = [];

  const funcPattern = /\bfunc\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)\s*\(([A-Za-z_][A-Za-z0-9_,\s]*[A-Za-z_][A-Za-z0-9_]*\s+[A-Za-z_][A-Za-z0-9_]+)\)/gu;

  for (const match of findAllMatches(text, funcPattern)) {
    const openBraceIndex = text.indexOf('{', match.endOffset);

    if (openBraceIndex < 0) {
      continue;
    }

    const closeBraceIndex = findMatchingDelimiter(
      text,
      openBraceIndex,
      '{',
      '}',
    );

    if (closeBraceIndex < 0) {
      continue;
    }

    const body = text.slice(openBraceIndex + 1, closeBraceIndex);
    const cleanBody = stripNestedFunctionBodies(body);

    const stmtCount = cleanBody
      .split('\n')
      .filter((line) => line.trim() && !line.trim().startsWith('//')).length;

    if (stmtCount <= 1) {
      continue;
    }

    const bareReturnPattern = /^[ \t]*return\s*$/gmu;

    for (const innerMatch of findAllMatches(cleanBody, bareReturnPattern)) {
      const absoluteStart = openBraceIndex + 1 + innerMatch.startOffset;
      const absoluteEnd = openBraceIndex + 1 + innerMatch.endOffset;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteEnd,
          text: innerMatch.matchedText,
        }),
      );
    }
  }

  return findings;
}

/**
 * Flags boolean literals in binary expressions (`== true`, `!= true`,
 * `== false`, `!= false`, and their reversed operand forms).
 */
function collectBooleanLiteralInExpressionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.booleanLiteralInExpression;
  const cleanedText = replaceStringContents(text);

  return collectMatchedFacts({
    text: cleanedText,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /(?:==|!=)\s*\b(?:true|false)\b|\b(?:true|false)\b\s*(?:==|!=)/gu,
  });
}

/**
 * Flags unexported (lowercase) type/struct declarations whose field names
 * start with a capital letter. This is often unintentional: unexported
 * types should typically have unexported fields to avoid exposing
 * implementation details through the package boundary.
 * Marked experimental — legitimate exceptions exist (e.g., ID, URL fields).
 */
function collectUnexportedCapitalNameFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.unexportedCapitalName;
  const findings: ObservedFact[] = [];

  const typePattern = /\btype\s+([a-z]\w*)\s+struct\s*\{/gu;

  for (const match of findAllMatches(text, typePattern)) {
    const structName = match.matchedText.match(
      /\btype\s+([a-z]\w*)\s+struct/u,
    )?.[1];

    if (!structName) {
      continue;
    }

    const openBraceIndex = text.indexOf('{', match.startOffset);
    const closeBraceIndex = findMatchingDelimiter(
      text,
      openBraceIndex,
      '{',
      '}',
    );

    if (closeBraceIndex < 0) {
      continue;
    }

    const body = text.slice(openBraceIndex + 1, closeBraceIndex);
    const fieldPattern = /^\s+([A-Z]\w*)\s/mu;

    if (fieldPattern.test(body)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: closeBraceIndex + 1,
          text: text.slice(match.startOffset, closeBraceIndex + 1),
        }),
      );
    }
  }

  return findings;
}

/**
 * Flags `http.NewRequest(url, body, nil)` and
 * `http.NewRequestWithContext(ctx, url, body, nil)` where the body is
 * a literal `nil`. Use `http.NoBody` instead.
 */
function collectHttpNobodyNilFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.httpNobodyNil;

  const cleanedText = replaceStringContents(text);

  return collectMatchedFacts({
    text: cleanedText,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\bhttp\.(?:NewRequest(?:WithContext)?)\s*\([^,]+,\s*[^,]+,\s*nil\b/gu,
  });
}

/**
 * Flags `strings.Join([]string{...}, "")` with an empty separator
 * (prefer direct concatenation) and `fmt.Sprintf("%s%s...", a, b, ...)`
 * with only `%s` placeholders (prefer `strings.Join` or concatenation).
 */
function collectStringConcatSimplifyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.stringConcatSimplify;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const stringsJoinPattern =
    /\bstrings\.Join\s*\([^,]+,\s*""\s*\)/gu;

  for (const match of findAllMatches(cleanedText, stringsJoinPattern)) {
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
      }),
    );
  }

  const fmtSprintfPattern = /\bfmt\.Sprintf\s*\(/gu;

  for (const match of findAllMatches(text, fmtSprintfPattern)) {
    const parenStart = text.indexOf('(', match.startOffset);
    if (parenStart < 0) continue;

    const closeParen = findMatchingDelimiter(text, parenStart, '(', ')');
    if (closeParen < 0) continue;

    const callText = text.slice(match.startOffset, closeParen + 1);
    const formatMatch = callText.match(/fmt\.Sprintf\s*\(\s*"([^"]*)"\s*,/u);

    if (!formatMatch) continue;

    const formatStr = formatMatch[1];
    const onlySPlaceholders = /^%s+$/u.test(formatStr.replace(/%%/gu, ''));

    if (onlySPlaceholders) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: closeParen + 1,
          text: callText,
        }),
      );
    }
  }

  return findings;
}

/**
 * GO-W1001: BEST-EFFORT heuristic. Detects patterns where a function returns
 * a concrete pointer type (e.g. `*MyError`) but the caller assigns it to an
 * `error` interface variable and then compares to nil — the nil check is
 * always false because the interface is non-nil even when the concrete value
 * is nil.
 *
 * Regex-only approach — limited to obvious patterns. Marked experimental.
 */
function collectImpossibleInterfaceNilCheckFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.impossibleInterfaceNilCheck;
  const findings: ObservedFact[] = [];

  const errDeclPattern = /\bvar\s+(\w+)\s+error\b/gu;

  for (const match of findAllMatches(text, errDeclPattern)) {
    const varNameMatch = /\bvar\s+(\w+)\s+error\b/u.exec(match.matchedText);
    const varName = varNameMatch?.[1];
    if (!varName) continue;

    const afterDecl = text.slice(match.endOffset);
    const nilCheckPattern = new RegExp(
      `(?<![A-Za-z_0-9])${escapeRegex(varName)}\\s*(?:!=\\s*nil|==\\s*nil)`,
      'gu',
    );

    if (nilCheckPattern.test(afterDecl)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: match.matchedText,
        }),
      );
    }
  }

  return findings;
}

/**
 * GO-W1002: Flags `if COND { ... } else if COND { ... }` where the same
 * condition text appears verbatim on both branches. Text comparison only —
 * cannot detect semantic equivalence. Marked experimental.
 */
function collectDuplicateIfElseConditionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_CORRECTNESS_FACT_KINDS.duplicateIfElseCondition;
  const findings: ObservedFact[] = [];

  const ifPattern = /\bif\s+(.+?)\s*\{/gi;

  for (const ifMatch of findAllMatches(text, ifPattern)) {
    const conditionMatch = /\bif\s+(.+?)\s*\{/i.exec(ifMatch.matchedText);
    const condition = conditionMatch?.[1]?.trim();
    if (!condition) continue;

    const afterIf = text.slice(ifMatch.endOffset);
    const elseIfPattern = new RegExp(
      `else\\s+if\\s+${escapeRegex(condition)}\\s*\\{`,
      'giu',
    );

    const elseIfMatch = findAllMatches(afterIf, elseIfPattern);

    if (elseIfMatch.length > 0) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: ifMatch.startOffset,
          endOffset: ifMatch.endOffset + afterIf.indexOf(elseIfMatch[0].matchedText, 0) + elseIfMatch[0].matchedText.length,
          text: `if ${condition} { ... } else if ${condition} {`,
        }),
      );
    }
  }

  return findings;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}
