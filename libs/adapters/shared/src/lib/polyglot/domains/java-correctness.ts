import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches, findMatchingDelimiter } from '../../runtime';
import { createOffsetFact } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const JAVA_CORRECTNESS_FACT_KINDS = {
  emptyCatch: 'java.correctness.empty-catch',
  equalsOnArray: 'java.correctness.equals-on-array',
  syncOnStringLiteral: 'java.correctness.sync-on-string-literal',
  catchNullPointer: 'java.correctness.catch-null-pointer',
  unsafeOptionalGet: 'java.correctness.unsafe-optional-get',
  returnInFinally: 'java.correctness.return-in-finally',
} as const;

export interface CollectJavaCorrectnessFactsOptions {
  text: string;
  detector: string;
}

export function collectJavaCorrectnessFacts(
  options: CollectJavaCorrectnessFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectEmptyCatchFacts(text, detector),
    ...collectEqualsOnArrayFacts(text, detector),
    ...collectSyncOnStringLiteralFacts(text, detector),
    ...collectCatchNullPointerFacts(text, detector),
    ...collectUnsafeOptionalGetFacts(text, detector),
    ...collectReturnInFinallyFacts(text, detector),
  ];
}

function collectEmptyCatchFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.emptyCatch,
    appliesTo: 'block',
    pattern:
      /\bcatch\s*\([^)]*\)\s*\{\s*(?:\/\/[^\n]*\s*|\/\*[\s\S]*?\*\/\s*)*\}/gu,
  });
}

function collectSyncOnStringLiteralFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.syncOnStringLiteral,
    appliesTo: 'block',
    pattern: /\bsynchronized\s*\(\s*(?:"[^"\n]*"|'[^'\n]*')\s*\)/gu,
  });
}

function collectCatchNullPointerFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.catchNullPointer,
    appliesTo: 'block',
    pattern: /\bcatch\s*\(\s*NullPointerException\b[^)]*\)/gu,
  });
}

function collectEqualsOnArrayFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const arrayNames = collectArrayVariableNames(text);

  if (arrayNames.size === 0) {
    return [];
  }

  const kind = JAVA_CORRECTNESS_FACT_KINDS.equalsOnArray;
  const findings: ObservedFact[] = [];

  for (const name of arrayNames) {
    const callPattern = new RegExp(
      `(?<![A-Za-z_$0-9.])${escapeRegex(name)}\\.equals\\s*\\(`,
      'gu',
    );

    for (const match of findAllMatches(text, callPattern)) {
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

function collectUnsafeOptionalGetFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const optionalNames = collectOptionalVariableNames(text);

  if (optionalNames.size === 0) {
    return [];
  }

  const kind = JAVA_CORRECTNESS_FACT_KINDS.unsafeOptionalGet;
  const findings: ObservedFact[] = [];
  const lineOffsets = computeLineOffsets(text);

  for (const name of optionalNames) {
    const getPattern = new RegExp(
      `(?<![A-Za-z_$0-9.])${escapeRegex(name)}\\.get\\s*\\(\\s*\\)`,
      'gu',
    );
    const guardPattern = new RegExp(
      `(?<![A-Za-z_$0-9.])${escapeRegex(
        name,
      )}\\.(?:isPresent|isEmpty|ifPresent|ifPresentOrElse|orElse|orElseGet|orElseThrow|map|flatMap|filter)\\b`,
      'gu',
    );

    const guardMatches = findAllMatches(text, guardPattern);
    const guardLines = new Set<number>(
      guardMatches.map((guard) => offsetToLine(guard.startOffset, lineOffsets)),
    );

    for (const match of findAllMatches(text, getPattern)) {
      const line = offsetToLine(match.startOffset, lineOffsets);
      const hasNearbyGuard = Array.from(guardLines).some(
        (guardLine) => Math.abs(guardLine - line) <= 3,
      );

      if (hasNearbyGuard) {
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
  }

  return findings;
}

function collectReturnInFinallyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.returnInFinally;
  const findings: ObservedFact[] = [];

  for (const match of text.matchAll(/\bfinally\s*\{/gu)) {
    const openIndex = (match.index ?? -1) + match[0].length - 1;

    if (openIndex < 0) {
      continue;
    }

    const closeIndex = findMatchingDelimiter(text, openIndex, '{', '}');

    if (closeIndex < 0) {
      continue;
    }

    const innerText = text.slice(openIndex + 1, closeIndex);
    const controlPattern = /\b(?:return|break|continue|throw)\b/gu;
    const cleanedInner = stripNestedBlocks(innerText);

    for (const innerMatch of cleanedInner.matchAll(controlPattern)) {
      const innerStart = innerMatch.index ?? 0;
      const absoluteStart = openIndex + 1 + innerStart;
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

function collectArrayVariableNames(text: string): Set<string> {
  const names = new Set<string>();

  const declarationPattern =
    /\b(?:[A-Za-z_$][A-Za-z0-9_$.]*(?:<[^<>;\n]+>)?)(?:\s*\[\s*\])+\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/gu;

  for (const match of text.matchAll(declarationPattern)) {
    names.add(match[1]);
  }

  return names;
}

function collectOptionalVariableNames(text: string): Set<string> {
  const names = new Set<string>();

  const typedPattern =
    /\b(?:Optional|OptionalInt|OptionalLong|OptionalDouble)(?:<[^<>;\n]+>)?\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/gu;
  for (const match of text.matchAll(typedPattern)) {
    names.add(match[1]);
  }

  const assignmentPattern =
    /\b(?:var\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*Optional\.(?:of|ofNullable|empty)\s*\(/gu;
  for (const match of text.matchAll(assignmentPattern)) {
    names.add(match[1]);
  }

  return names;
}

function computeLineOffsets(text: string): number[] {
  const offsets: number[] = [0];

  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === '\n') {
      offsets.push(index + 1);
    }
  }

  return offsets;
}

function offsetToLine(offset: number, lineOffsets: number[]): number {
  let low = 0;
  let high = lineOffsets.length - 1;

  while (low <= high) {
    const mid = (low + high) >>> 1;
    const start = lineOffsets[mid];

    if (start === offset) {
      return mid;
    }

    if (start < offset) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  return Math.max(0, low - 1);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

/**
 * Replace nested block contents (lambdas, anonymous classes, local classes)
 * with spaces so that control-flow keywords inside them do not count toward the
 * enclosing finally block. Brace counts are preserved at depth > 0 to avoid
 * altering offsets.
 */
function stripNestedBlocks(source: string): string {
  let depth = 0;
  const chars: string[] = source.split('');

  for (let index = 0; index < chars.length; index += 1) {
    const char = chars[index];

    if (char === '{') {
      if (depth > 0) {
        chars[index] = ' ';
      }
      depth += 1;
      continue;
    }

    if (char === '}') {
      depth -= 1;
      if (depth > 0) {
        chars[index] = ' ';
      }
      continue;
    }

    if (depth > 1) {
      chars[index] = char === '\n' ? '\n' : ' ';
    }
  }

  return chars.join('');
}
