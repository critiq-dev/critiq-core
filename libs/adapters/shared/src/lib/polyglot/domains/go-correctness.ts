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
  deferInLoop: 'go.correctness.defer-in-loop',
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

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}
