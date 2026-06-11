import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches, findMatchingDelimiter } from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';
import type { TrackedIdentifierState } from '../types';

export interface PolyglotPerformancePathOptions {
  text: string;
  path: string;
  detector: string;
}

export interface PhpPerformanceFactsOptions extends PolyglotPerformancePathOptions {
  state?: TrackedIdentifierState;
  matchesTainted?: (
    expression: string,
    state: TrackedIdentifierState,
  ) => boolean;
}

export const PHP_PERFORMANCE_FACT_KINDS = {
  noRegexConstructionInLoop: 'php.performance.no-regex-construction-in-loop',
  noSyncFsInRequestPath: 'php.performance.no-sync-fs-in-request-path',
  expensiveLoopCondition: 'php.performance.expensive-loop-condition',
  noUnboundedConcurrency: 'php.performance.no-unbounded-concurrency',
} as const;

function collectSharedPerformanceFacts(
  options: PolyglotPerformancePathOptions,
  languagePrefix: string,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: `${languagePrefix}.performance.no-regex-construction-in-loop`,
      pattern: /\b(?:for|while)\b[\s\S]{0,200}\b(?:new\s+RegExp|regexp\.Compile|Regex::new)\s*\(/g,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: `${languagePrefix}.performance.no-sync-fs-in-request-path`,
      pattern:
        /\b(?:req|request|ctx|context)\b[\s\S]{0,260}\b(?:ReadFileSync|WriteFileSync|readFileSync|writeFileSync|os\.ReadFile|Files\.(?:readAllBytes|write)|File::open|std::fs::(?:read_to_string|read|write))\b/g,
      appliesTo: 'function',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: `${languagePrefix}.performance.no-unbounded-concurrency`,
      pattern:
        /\b(?:Promise\.all|CompletableFuture\.allOf|asyncio\.gather|Task\.WhenAll|tokio::join!|futures::future::join_all)\s*\([^)]*(?:map|items|records|users|rows|list|iter)\b[^)]*\)/g,
      appliesTo: 'block',
    }),
  ];
}

export const GO_PERFORMANCE_FACT_KINDS = {
  combineAppendCalls: 'go.performance.combine-append-calls',
  avoidLargeParamCopy: 'go.performance.avoid-large-param-copy',
  avoidStringIndexAlloc: 'go.performance.avoid-string-index-alloc',
  avoidLargeRangeCopy: 'go.performance.avoid-large-range-copy',
  avoidLargeLoopCopy: 'go.performance.avoid-large-loop-copy',
  reorderOperands: 'go.performance.reorder-operands',
  nonIdiomaticSliceZeroing: 'go.performance.non-idiomatic-slice-zeroing',
  utf8DecodeRune: 'go.performance.utf8-decode-rune',
  fmtFprint: 'go.performance.fmt-fprint',
  writerWriteString: 'go.performance.iowriter-write-string',
} as const;

export function collectGoPerformanceFacts(
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return dedupeFacts([
    ...collectSharedPerformanceFacts(options, 'go'),
    ...collectGoCombineAppendCallsFacts(text, detector),
    ...collectGoAvoidLargeParamCopyFacts(text, detector),
    ...collectGoAvoidStringIndexAllocFacts(text, detector),
    ...collectGoAvoidLargeRangeCopyFacts(text, detector),
    ...collectGoAvoidLargeLoopCopyFacts(text, detector),
    ...collectGoReorderOperandsFacts(text, detector),
    ...collectGoNonIdiomaticSliceZeroingFacts(text, detector),
    ...collectGoUtf8DecodeRuneFacts(text, detector),
    ...collectGoFmtFprintFacts(text, detector),
    ...collectGoIOWriterWriteStringFacts(text, detector),
  ]);
}

/**
 * CRT-P0001: Detects consecutive `xs = append(xs, ...)` calls on the same slice.
 * Multiple append calls can be combined into a single call to reduce allocations.
 */
function collectGoCombineAppendCallsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_PERFORMANCE_FACT_KINDS.combineAppendCalls;
  const findings: ObservedFact[] = [];

  const appendPattern = /^[ \t]*([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*append\s*\(/gmu;

  const matches = findAllMatches(text, appendPattern);

  let i = 0;
  while (i < matches.length) {
    const varName = matches[i].matchedText.split('=')[0].trim();
    const groupStart = i;
    let groupEnd = i;

    while (
      groupEnd + 1 < matches.length &&
      matches[groupEnd + 1].matchedText.split('=')[0].trim() === varName
    ) {
      groupEnd += 1;
    }

    if (groupEnd - groupStart >= 1) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: matches[groupStart].startOffset,
          endOffset: matches[groupEnd].endOffset,
          text: matches.slice(groupStart, groupEnd + 1).map((m) => m.matchedText.trim()).join('\n'),
        }),
      );
    }

    i = groupEnd + 1;
  }

  return findings;
}

/**
 * CRT-P0003: Flags function declarations where a parameter is a fixed-size array
 * with size > 80 bytes (array size >= 3 digits), suggesting excessive copying.
 */
function collectGoAvoidLargeParamCopyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_PERFORMANCE_FACT_KINDS.avoidLargeParamCopy,
    appliesTo: 'block',
    pattern:
      /\bfunc\s+\w+\s*\([^)]*\b\w+\s+\[(\d{3,})\]\w+/g,
  });
}

/**
 * CRT-P0004: Flags `strings.Index(string(x), ...)` where the explicit string()
 * conversion on a non-string argument causes allocation.
 */
function collectGoAvoidStringIndexAllocFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_PERFORMANCE_FACT_KINDS.avoidStringIndexAlloc,
    appliesTo: 'block',
    pattern:
      /\bstrings\.Index\s*\(\s*string\s*\([^)]+\)\s*,/g,
  });
}

/**
 * CRT-P0005: Flags `for _, x := range xs` where xs is a large fixed-size array
 * (size >= 100). Each iteration copies the array element by value.
 */
function collectGoAvoidLargeRangeCopyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_PERFORMANCE_FACT_KINDS.avoidLargeRangeCopy;
  const findings: ObservedFact[] = [];

  const largeArrayVars = new Set<string>();
  const declPattern = /\bvar\s+([A-Za-z_][A-Za-z0-9_]*)\s+\[(\d{3,})\]\w+/gu;

  for (const match of findAllMatches(text, declPattern)) {
    largeArrayVars.add(match.matchedText.split(/\s+/u)[1]);
  }

  if (largeArrayVars.size === 0) {
    return findings;
  }

  const rangePattern = /for\s+_\s*,\s*(\w+)\s*:=\s*range\s+(\w+)/gu;

  for (const match of findAllMatches(text, rangePattern)) {
    const arrayVar = match.matchedText.replace(/for\s+_\s*,\s*\w+\s*:=\s*range\s+/u, '').trim();

    if (largeArrayVars.has(arrayVar)) {
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
 * CRT-P0006: Flags `for _, x := range xs` where xs is a slice of large fixed-size
 * arrays (e.g., `make([][1024]byte, n)`). Each iteration copies the element by value.
 */
function collectGoAvoidLargeLoopCopyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_PERFORMANCE_FACT_KINDS.avoidLargeLoopCopy;
  const findings: ObservedFact[] = [];

  const largeSliceVars = new Set<string>();
  const makePattern = /\b(\w+)\s*(?::?=|\s*=\s*)\s*make\s*\(\s*\[\]\[(\d{3,})\]\w+/gu;

  for (const match of findAllMatches(text, makePattern)) {
    largeSliceVars.add(match.matchedText.split(/[=:]+/u)[0].trim());
  }

  if (largeSliceVars.size === 0) {
    return findings;
  }

  const rangePattern = /for\s+_\s*,\s*(\w+)\s*:=\s*range\s+(\w+)/gu;

  for (const match of findAllMatches(text, rangePattern)) {
    const rangeVar = match.matchedText.replace(/for\s+_\s*,\s*\w+\s*:=\s*range\s+/u, '').trim();

    if (largeSliceVars.has(rangeVar)) {
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
 * GO-P3001: Flags boolean `&&`/`||` expressions where left operand is a
 * function call and right operand is a simple identifier or constant.
 * Reordering may enable short-circuit optimization.
 */
function collectGoReorderOperandsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_PERFORMANCE_FACT_KINDS.reorderOperands;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const pattern =
    /([A-Za-z_][A-Za-z0-9_.]*)\s*\([^)]*\)\s*(\|\||&&)\s*([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()/gu;

  const regexMatches = Array.from(cleanedText.matchAll(pattern));

  for (const match of regexMatches) {
    const rightOperand = match[3];
    const matchIndex = match.index ?? 0;

    if (!rightOperand || /^[A-Z]/u.test(rightOperand)) {
      continue;
    }

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: matchIndex,
        endOffset: matchIndex + match[0].length,
        text: text.slice(matchIndex, matchIndex + match[0].length),
      }),
    );
  }

  return findings;
}

/**
 * GO-P4001: Detects three-clause `for i := 0; i < len(x); i++ { x[i] = <zero> }`
 * loops. Go optimizes `for i := range x { x[i] = <zero> }` but not the explicit
 * three-clause form.
 */
function collectGoNonIdiomaticSliceZeroingFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_PERFORMANCE_FACT_KINDS.nonIdiomaticSliceZeroing;
  const findings: ObservedFact[] = [];

  const forPattern = /for\s+(\w+)\s*:=\s*0\s*;\s*\1\s*<\s*len\((\w+)\)\s*;\s*\1\+\+/gu;

  const regexMatches = Array.from(text.matchAll(forPattern));

  for (const regMatch of regexMatches) {
    const indexVar = regMatch[1];
    const sliceName = regMatch[2];
    if (!indexVar || !sliceName) continue;

    const matchStart = regMatch.index ?? 0;
    const matchEnd = matchStart + regMatch[0].length;

    const bodyStart = text.indexOf('{', matchEnd - 1);
    if (bodyStart < 0) continue;

    const closeBraceIndex = findMatchingDelimiter(text, bodyStart, '{', '}');
    if (closeBraceIndex < 0) continue;

    const body = text.slice(bodyStart + 1, closeBraceIndex);
    const cleanBody = stripNestedFunctionBodies(body);

    const zeroPattern = new RegExp(
      `(?<![A-Za-z_0-9])${escapeRegex(sliceName)}\\s*\\[${escapeRegex(indexVar)}\\]\\s*=\\s*(?:0|0\\.0|""|false|nil|[A-Za-z_][A-Za-z0-9_]*\\{\\})`,
      'u',
    );

    if (zeroPattern.test(cleanBody)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: matchStart,
          endOffset: matchEnd,
          text: regMatch[0],
        }),
      );
    }
  }

  return findings;
}

/**
 * GO-P4006: Detects `[]rune(str)[0]` pattern which allocates a rune slice.
 * Prefer `utf8.DecodeRuneInString(str)` for single-rune access.
 */
function collectGoUtf8DecodeRuneFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_PERFORMANCE_FACT_KINDS.utf8DecodeRune;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const pattern = /\[\]rune\s*\([^)]+\)\s*\[0\]/gu;

  for (const match of findAllMatches(cleanedText, pattern)) {
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
 * GO-P4007: Detects `w.Write([]byte(fmt.Sprintf(...)))` and
 * `w.Write(fmt.Sprint*(...))` patterns that should use `fmt.Fprint(w, ...)`.
 */
function collectGoFmtFprintFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_PERFORMANCE_FACT_KINDS.fmtFprint;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const patternA = /\.Write\(\s*\[\]byte\(\s*fmt\.Sprintf?\(/gu;

  for (const match of findAllMatches(cleanedText, patternA)) {
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

  const patternB = /\.Write\(\s*fmt\.Sprint[fln]?\s*\(/gu;

  for (const match of findAllMatches(cleanedText, patternB)) {
    const fullText = text.slice(match.startOffset, match.endOffset);

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: fullText,
      }),
    );
  }

  return findings;
}

/**
 * GO-P4008: Detects `w.Write([]byte(s))` and `io.WriteString(w, s)` patterns
 * where `(io.StringWriter).WriteString` is more efficient for string writes.
 * Skips `strings.Builder.Write([]byte(...))` which has an efficient internal path.
 */
function collectGoIOWriterWriteStringFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_PERFORMANCE_FACT_KINDS.writerWriteString;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const writeBytePattern = /\.Write\(\s*\[\]byte\(/gu;

  for (const match of findAllMatches(cleanedText, writeBytePattern)) {
    const beforeText = text.slice(0, match.startOffset);
    const builderMatch = /strings?\.Builder\s*$/u.exec(
      beforeText.match(/([A-Za-z_.][A-Za-z0-9_.]*)\s*$/u)?.[0] ?? '',
    );
    if (builderMatch) continue;

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

  const ioWriteStringPattern = /io\.WriteString\(/gu;

  for (const match of findAllMatches(cleanedText, ioWriteStringPattern)) {
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

function collectThreadAsRunnableFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.thread-as-runnable',
    appliesTo: 'block',
    pattern:
      /\.(?:submit|execute|schedule)\s*\(\s*new\s+Thread\s*\(/gu,
  });
}

function collectUrlInCollectionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.url-in-collection',
    appliesTo: 'file',
    pattern:
      /\b(?:HashMap|HashSet|Map|Set)\b\s*<\s*(?:[\w.]+\s*\.\s*)?\bURL\s*(?:,|>)/gu,
  });
}

function collectInefficientStringConstructorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.inefficient-string-constructor',
    appliesTo: 'block',
    pattern:
      /new\s+String\s*\(\s*"[^"]*"\s*\)/gu,
  });
}

function collectEmptyStringConstructorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.empty-string-constructor',
    appliesTo: 'block',
    pattern:
      /new\s+String\s*\(\s*\)/gu,
  });
}

function collectStringToStringFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.string-to-string',
    appliesTo: 'block',
    pattern:
      /"[^"]*"\s*\.\s*toString\s*\(/gu,
  });
}

function collectExplicitGcFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.explicit-gc',
    appliesTo: 'block',
    pattern:
      /\bSystem\s*\.\s*gc\s*\(|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*gc\s*\(/gu,
  });
}

function collectBooleanConstructorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.boxed-boolean-constructor',
    appliesTo: 'block',
    pattern:
      /new\s+Boolean\s*\(/gu,
  });
}

function collectIntegerLongConstructorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.boxed-integer-constructor',
    appliesTo: 'block',
    pattern:
      /new\s+(?:Integer|Long)\s*\(/gu,
  });
}

function collectPatternCompileInLoopFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.pattern-compile-in-loop',
    appliesTo: 'block',
    pattern:
      /\b(?:for|while)\b[\s\S]{0,300}\bPattern\s*\.\s*compile\s*\(/g,
  });
}

function collectNonZeroToArrayFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.non-zero-to-array',
    appliesTo: 'block',
    pattern:
      /toArray\s*\(\s*new\s+\w+\s*\[[^\]]*[1-9][^\]]*\]/g,
  });
}

function collectKeySetInsteadOfEntrySetFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'java.performance.keyset-instead-of-entryset',
      appliesTo: 'block',
      pattern:
        /for\s*\([^)]*:\s*\w+\.keySet\(\)\)[\s\S]{0,400}?\.get\s*\(/g,
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'java.performance.keyset-instead-of-entryset',
      appliesTo: 'block',
      pattern:
        /while\s*\([^)]*\.keySet\(\)\s*\.\s*iterator\(\)[\s\S]{0,400}?\.get\s*\(/g,
    }),
  ];
}

function collectReplaceAllInsteadOfReplaceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.replaceall-instead-of-replace',
    appliesTo: 'block',
    pattern:
      /\.replaceAll\s*\(\s*"[^\\^$.*+?()[\]{}|]*"\s*,/g,
  });
}

function collectSingleCharStringIndexOfFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.single-char-string-indexof',
    appliesTo: 'block',
    pattern:
      /\.(?:indexOf|lastIndexOf|contains)\s*\(\s*"[^"]"\s*\)/g,
  });
}

/**
 * JAVA-P1005: Detects `collection.removeAll(collection)` calls that should
 * be `collection.clear()`. Compares the receiver expression (before `.removeAll`)
 * with the argument expression (inside parens) for structural equality.
 *
 * Edge: chained calls like `obj.getItems().removeAll(obj.getItems())` are detected.
 * Edge: wrapped calls like `collection.removeAll(singleton(collection))` do NOT match
 *       because the arg text differs from receiver text.
 */
function collectRemoveallToClearFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = 'java.performance.removeall-to-clear';
  const findings: ObservedFact[] = [];

  const pattern = /([A-Za-z_][\w.]*(?:\[[^\]]+\])?)\s*\.\s*removeAll\s*\(/g;

  const regexMatches = Array.from(text.matchAll(pattern));
  for (const match of regexMatches) {
    const callStart = match.index ?? 0;
    const receiver = (match[1] ?? '').trim();
    if (!receiver) continue;

    const closeParen = findMatchingDelimiter(text, callStart + match[0].length - 1, '(', ')');
    if (closeParen < 0) continue;

    const argText = text.slice(callStart + match[0].length, closeParen).trim();

    const strippedReceiver = receiver.replace(/\s+/g, '');
    const strippedArg = argText.replace(/\s+/g, '');

    if (strippedReceiver === strippedArg) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: callStart,
          endOffset: closeParen + 1,
          text: text.slice(callStart, closeParen + 1),
        }),
      );
    }
  }

  return findings;
}

/**
 * JAVA-P1006: Detects String concatenation using `+=` or `= ... + ...` inside
 * loop bodies. Two-pass approach:
 * 1. Find loop bodies (for/while/do-while) using findMatchingDelimiter
 * 2. Inside each body, detect `var += "..."` and `var = var + "..."` patterns
 *
 * Pre-scans for `String ` variable declarations in the method body to reduce
 * false positives from numeric `+=` in loops.
 * confidence: 0.75 acknowledges the heuristic nature.
 */
function collectStringConcatInLoopFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = 'java.performance.string-concat-in-loop';
  const findings: ObservedFact[] = [];

  const loopPattern = /\b(for|while|do)\s*\(/g;

  for (const loopMatch of findAllMatches(text, loopPattern)) {
    const loopKeyword = loopMatch.matchedText.split('(')[0].trim();

    let conditionEnd: number;
    if (loopKeyword === 'do') {
      const doBodyStart = text.indexOf('{', loopMatch.endOffset);
      if (doBodyStart < 0) continue;
      conditionEnd = doBodyStart;
    } else {
      const closeParen = findMatchingDelimiter(text, loopMatch.startOffset, '(', ')');
      if (closeParen < 0) continue;
      conditionEnd = closeParen;
    }

    const bodyOpen = text.indexOf('{', conditionEnd);
    if (bodyOpen < 0) continue;
    const bodyClose = findMatchingDelimiter(text, bodyOpen, '{', '}');
    if (bodyClose < 0) continue;

    const body = text.slice(bodyOpen + 1, bodyClose);

    const stringVars = new Set<string>();
    const stringDeclPattern = /\bString\s+(\w+)\s*[=;]/g;
    for (const decl of body.matchAll(stringDeclPattern)) {
      if (decl[1]) stringVars.add(decl[1]);
    }
    const beforeLoop = text.slice(0, bodyOpen);
    for (const decl of beforeLoop.matchAll(stringDeclPattern)) {
      if (decl[1]) stringVars.add(decl[1]);
    }

    const compoundAssignPattern = /(\w[\w.]*)\s*\+=\s*/g;
    for (const caMatch of findAllMatches(body, compoundAssignPattern)) {
      const lhsVar = caMatch.matchedText.match(/^(\w[\w.]*)/)?.[1] ?? '';
      if (!lhsVar || !stringVars.has(lhsVar)) continue;
      const absOffset = bodyOpen + 1 + caMatch.startOffset;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'function',
          kind,
          startOffset: absOffset,
          endOffset: absOffset + caMatch.matchedText.length,
          text: text.slice(absOffset, absOffset + caMatch.matchedText.length),
        }),
      );
    }

    const concatPattern = /(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*\+/g;
    for (const coMatch of findAllMatches(body, concatPattern)) {
      const lhsVar = coMatch.matchedText.match(/^(\w[\w.]*)/)?.[1] ?? '';
      const rhsFirst = coMatch.matchedText.split('=')[1]?.trim().split('+')[0]?.trim() ?? '';
      if (lhsVar === rhsFirst && stringVars.has(lhsVar)) {
        const absOffset = bodyOpen + 1 + coMatch.startOffset;
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: absOffset,
            endOffset: absOffset + coMatch.matchedText.length,
            text: text.slice(absOffset, absOffset + coMatch.matchedText.length),
          }),
        );
      }
    }
  }

  return findings;
}

/**
 * JAVA-P1007: Detects expensive methods annotated with @WorkerThread / @Expensive
 * called from within @MainThread / @UIThread / @PerformanceCritical annotated methods.
 *
 * Multi-pass approach:
 * 1. Scan entire file for methods annotated with @WorkerThread or @Expensive
 * 2. Scan for methods annotated with @MainThread, @UIThread, or @PerformanceCritical
 * 3. Within those perf-critical method bodies, search for calls to expensive method names
 *
 * Stability: experimental — accepts false positives/negatives from name collisions.
 */
function collectExpensiveMethodOnUiThreadFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = 'java.performance.expensive-method-on-ui-thread';
  const findings: ObservedFact[] = [];

  const annotationPattern =
    /@(?:WorkerThread|Expensive|androidx\.annotation\.WorkerThread|javax\.annotation\.concurrent\.WorkerThread)\s+(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*(\w+(?:<[^>]+>)?)\s+(\w+)\s*\(/g;

  const expensiveMethods = new Map<string, number>();

  for (const match of text.matchAll(annotationPattern)) {
    const methodName = match[2];
    if (methodName) {
      expensiveMethods.set(methodName, match.index ?? 0);
    }
  }

  if (expensiveMethods.size === 0) return findings;

  const perfCriticalPattern =
    /@(?:MainThread|UIThread|PerformanceCritical|androidx\.annotation\.MainThread|androidx\.annotation\.UIThread)\s+(?:(?:public|private|protected|static|final|synchronized|abstract)\s+)*\w+(?:<[^>]+>)?\s+\w+\s*\(/g;

  for (const pcMatch of text.matchAll(perfCriticalPattern)) {
    const bodyStart = text.indexOf('{', pcMatch.index ?? 0);
    if (bodyStart < 0) continue;

    const bodyEnd = findMatchingDelimiter(text, bodyStart, '{', '}');
    if (bodyEnd < 0) continue;

    const body = text.slice(bodyStart + 1, bodyEnd);

    for (const methodName of expensiveMethods.keys()) {
      const callPattern = new RegExp(
        `\\b${methodName.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')}\\s*\\(`,
        'g',
      );

      for (const callMatch of body.matchAll(callPattern)) {
        const absOffset = bodyStart + 1 + (callMatch.index ?? 0);
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: absOffset,
            endOffset: absOffset + callMatch[0].length,
            text: text.slice(absOffset, absOffset + callMatch[0].length),
          }),
        );
      }
    }
  }

  return findings;
}

function collectFloatDoubleConstructorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: 'java.performance.boxed-double-constructor',
    appliesTo: 'block',
    pattern:
      /new\s+(?:Float|Double)\s*\(/gu,
  });
}

export function collectJavaPerformanceFacts(
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectSharedPerformanceFacts(options, 'java'),
    ...collectThreadAsRunnableFacts(text, detector),
    ...collectUrlInCollectionFacts(text, detector),
    ...collectInefficientStringConstructorFacts(text, detector),
    ...collectEmptyStringConstructorFacts(text, detector),
    ...collectStringToStringFacts(text, detector),
    ...collectExplicitGcFacts(text, detector),
    ...collectBooleanConstructorFacts(text, detector),
    ...collectIntegerLongConstructorFacts(text, detector),
    ...collectFloatDoubleConstructorFacts(text, detector),
    ...collectPatternCompileInLoopFacts(text, detector),
    ...collectNonZeroToArrayFacts(text, detector),
    ...collectKeySetInsteadOfEntrySetFacts(text, detector),
    ...collectReplaceAllInsteadOfReplaceFacts(text, detector),
    ...collectSingleCharStringIndexOfFacts(text, detector),
    ...collectRemoveallToClearFacts(text, detector),
    ...collectStringConcatInLoopFacts(text, detector),
    ...collectExpensiveMethodOnUiThreadFacts(text, detector),
  ];
}

export function collectPhpPerformanceFacts(
  options: PhpPerformanceFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: PHP_PERFORMANCE_FACT_KINDS.noRegexConstructionInLoop,
      pattern:
        /\b(?:for|while)\b[\s\S]{0,300}\bpreg_(?:match|match_all|replace|replace_callback|filter|grep|split)\s*\(/gu,
      appliesTo: 'block',
    }),
    ...collectPhpSyncFsInRequestPathFacts(options),
    ...collectMatchedFacts({
      text,
      detector,
      kind: PHP_PERFORMANCE_FACT_KINDS.expensiveLoopCondition,
      pattern:
        /\b(?:for|while)\s*\([\s\S]{0,240}?\b(?:count|sizeof|strlen|preg_match|preg_match_all|array_sum|in_array|file_get_contents|file_exists|glob)\s*\(/gu,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: PHP_PERFORMANCE_FACT_KINDS.noUnboundedConcurrency,
      appliesTo: 'block',
      pattern:
        /\b(?:GuzzleHttp\\Promise\\(?:all|unwrap)|Amp\\Promise\\all)\s*\(\s*\$\w+/gu,
    }),
  ];
}

const phpSyncFsCallPattern =
  /\b(?:file_get_contents|fopen|readfile|file|scandir|glob)\s*\(/gu;

function collectPhpSyncFsInRequestPathFacts(
  options: PhpPerformanceFactsOptions,
): ObservedFact[] {
  const { text, detector, state, matchesTainted } = options;

  if (!state || !matchesTainted) {
    return [];
  }

  return collectSnippetFacts({
    text,
    detector,
    kind: PHP_PERFORMANCE_FACT_KINDS.noSyncFsInRequestPath,
    pattern: phpSyncFsCallPattern,
    state,
    appliesTo: 'block',
    predicate: (snippet, scanState) =>
      isPhpSyncFsInRequestHandler(text, snippet.startOffset) &&
      matchesTainted(snippet.text, scanState),
  });
}

function isPhpSyncFsInRequestHandler(
  text: string,
  callStartOffset: number,
): boolean {
  const prefix = text.slice(0, callStartOffset);
  const functionStart = prefix.lastIndexOf('function');

  if (functionStart < 0) {
    return false;
  }

  return /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/u.test(
    text.slice(functionStart, callStartOffset),
  );
}

export function collectPythonPerformanceFacts(
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  return collectSharedPerformanceFacts(options, 'py');
}

export function collectRubyPerformanceFacts(
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  return collectSharedPerformanceFacts(options, 'ruby');
}

export const RUST_PERFORMANCE_FACT_KINDS = {
  singleCharStringLiteralPattern:
    'rust.performance.single-char-string-literal-pattern',
} as const;

function collectRustSingleCharStringLiteralFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_PERFORMANCE_FACT_KINDS.singleCharStringLiteralPattern,
    pattern:
      /\.(?:find|rfind|contains|starts_with|ends_with|strip_prefix|strip_suffix|trim_start_matches|trim_end_matches|trim_matches|split|rsplit|splitn|rsplitn|split_terminator|matches|rmatches|match_indices|rmatch_indices|replace|replacen)\s*\(\s*"(?:[^"\\]|\\.)"\s*[,)]/g,
    appliesTo: 'block',
  });
}

export function collectRustPerformanceFacts(
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  const { text, detector } = options;
  return [
    ...collectSharedPerformanceFacts(options, 'rust'),
    ...collectRustSingleCharStringLiteralFacts(text, detector),
  ];
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

function stripNestedFunctionBodies(source: string): string {
  const chars = source.split('');
  const funcPattern = /\bfunc\s*\(/gu;

  for (const match of source.matchAll(funcPattern)) {
    const matchStart = match.index ?? 0;
    const openBrace = findFunctionOpenBrace(source, matchStart);

    if (openBrace < 0) continue;

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

    if (closeBrace < 0) continue;

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

function replaceStringContents(source: string): string {
  return source.replace(/"([^"\\]*(?:\\.[^"\\]*)*)"/gu, (match) =>
    match[0] + match.slice(1, -1).replace(/[^\n]/gu, ' ') + '"',
  ).replace(/`[^`]*`/gu, (match) =>
    '`' + match.slice(1, -1).replace(/[^\n]/gu, ' ') + '`',
  );
}
