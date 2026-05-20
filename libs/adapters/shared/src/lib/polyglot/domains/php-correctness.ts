import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches, findMatchingDelimiter } from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const PHP_CORRECTNESS_FACT_KINDS = {
  duplicateArrayKey: 'php.correctness.duplicate-array-key',
  switchMultipleDefault: 'php.correctness.switch-multiple-default',
  errorSuppressionOperator: 'php.correctness.error-suppression-operator',
  unreachableAfterReturn: 'php.correctness.unreachable-after-return',
  nullsafeReturnedByReference: 'php.correctness.nullsafe-returned-by-reference',
} as const;

export interface CollectPhpCorrectnessFactsOptions {
  text: string;
  detector: string;
}

export function collectPhpCorrectnessFacts(
  options: CollectPhpCorrectnessFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return dedupeFacts([
    ...collectDuplicateArrayKeyFacts(text, detector),
    ...collectSwitchMultipleDefaultFacts(text, detector),
    ...collectErrorSuppressionOperatorFacts(text, detector),
    ...collectUnreachableAfterReturnFacts(text, detector),
    ...collectNullsafeReturnedByReferenceFacts(text, detector),
  ]);
}

function collectDuplicateArrayKeyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.duplicateArrayKey;
  const findings: ObservedFact[] = [];

  for (const literal of collectPhpArrayLiteralRanges(text)) {
    const seen = new Set<string>();
    const entries = splitTopLevelEntries(literal.content);

    for (const entry of entries) {
      const key = extractStaticArrayKey(entry.text);

      if (!key) {
        continue;
      }

      if (seen.has(key.normalized)) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: literal.startOffset + entry.startOffset,
            endOffset:
              literal.startOffset + entry.startOffset + key.raw.length,
            text: key.raw,
          }),
        );
        continue;
      }

      seen.add(key.normalized);
    }
  }

  return findings;
}

interface ArrayLiteralRange {
  startOffset: number;
  endOffset: number;
  content: string;
}

function collectPhpArrayLiteralRanges(text: string): ArrayLiteralRange[] {
  const ranges: ArrayLiteralRange[] = [];

  const arrayCallPattern = /\barray\s*\(/gu;

  for (const match of findAllMatches(text, arrayCallPattern)) {
    const openParen = match.endOffset - 1;
    const closeParen = findMatchingDelimiter(text, openParen, '(', ')');

    if (closeParen < 0) {
      continue;
    }

    const content = text.slice(openParen + 1, closeParen);

    if (!hasTopLevelArrow(content)) {
      continue;
    }

    ranges.push({
      startOffset: match.startOffset,
      endOffset: closeParen + 1,
      content,
    });
  }

  const stack: number[] = [];

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];

    if (char === '[') {
      stack.push(index);
      continue;
    }

    if (char !== ']' || stack.length === 0) {
      continue;
    }

    const start = stack.pop();

    if (start === undefined) {
      continue;
    }

    const content = text.slice(start + 1, index);

    if (!hasTopLevelArrow(content)) {
      continue;
    }

    ranges.push({
      startOffset: start,
      endOffset: index + 1,
      content,
    });
  }

  return ranges;
}

function hasTopLevelArrow(source: string): boolean {
  let depthParen = 0;
  let depthBracket = 0;
  let depthBrace = 0;

  for (let index = 0; index < source.length - 1; index += 1) {
    const char = source[index];
    const next = source[index + 1];

    if (char === '(') {
      depthParen += 1;
      continue;
    }
    if (char === ')') {
      depthParen = Math.max(0, depthParen - 1);
      continue;
    }
    if (char === '[') {
      depthBracket += 1;
      continue;
    }
    if (char === ']') {
      depthBracket = Math.max(0, depthBracket - 1);
      continue;
    }
    if (char === '{') {
      depthBrace += 1;
      continue;
    }
    if (char === '}') {
      depthBrace = Math.max(0, depthBrace - 1);
      continue;
    }

    if (
      char === '=' &&
      next === '>' &&
      depthParen === 0 &&
      depthBracket === 0 &&
      depthBrace === 0
    ) {
      return true;
    }
  }

  return false;
}

interface TopLevelEntry {
  text: string;
  startOffset: number;
}

function splitTopLevelEntries(source: string): TopLevelEntry[] {
  const entries: TopLevelEntry[] = [];
  let start = 0;
  let depthParen = 0;
  let depthBracket = 0;
  let depthBrace = 0;

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];

    if (char === '(') {
      depthParen += 1;
      continue;
    }
    if (char === ')') {
      depthParen = Math.max(0, depthParen - 1);
      continue;
    }
    if (char === '[') {
      depthBracket += 1;
      continue;
    }
    if (char === ']') {
      depthBracket = Math.max(0, depthBracket - 1);
      continue;
    }
    if (char === '{') {
      depthBrace += 1;
      continue;
    }
    if (char === '}') {
      depthBrace = Math.max(0, depthBrace - 1);
      continue;
    }

    if (
      char === ',' &&
      depthParen === 0 &&
      depthBracket === 0 &&
      depthBrace === 0
    ) {
      const textValue = source.slice(start, index).trim();

      if (textValue.length > 0) {
        const leftTrimmed = source.slice(start, index).match(/^\s*/u)?.[0].length ?? 0;
        entries.push({
          text: textValue,
          startOffset: start + leftTrimmed,
        });
      }

      start = index + 1;
    }
  }

  const last = source.slice(start).trim();

  if (last.length > 0) {
    const leftTrimmed = source.slice(start).match(/^\s*/u)?.[0].length ?? 0;
    entries.push({
      text: last,
      startOffset: start + leftTrimmed,
    });
  }

  return entries;
}

interface StaticArrayKey {
  raw: string;
  normalized: string;
}

function extractStaticArrayKey(entry: string): StaticArrayKey | undefined {
  if (entry.startsWith('...')) {
    return undefined;
  }

  let depthParen = 0;
  let depthBracket = 0;
  let depthBrace = 0;
  let separatorIndex = -1;

  for (let index = 0; index < entry.length - 1; index += 1) {
    const char = entry[index];
    const next = entry[index + 1];

    if (char === '(') {
      depthParen += 1;
      continue;
    }
    if (char === ')') {
      depthParen = Math.max(0, depthParen - 1);
      continue;
    }
    if (char === '[') {
      depthBracket += 1;
      continue;
    }
    if (char === ']') {
      depthBracket = Math.max(0, depthBracket - 1);
      continue;
    }
    if (char === '{') {
      depthBrace += 1;
      continue;
    }
    if (char === '}') {
      depthBrace = Math.max(0, depthBrace - 1);
      continue;
    }

    if (
      char === '=' &&
      next === '>' &&
      depthParen === 0 &&
      depthBracket === 0 &&
      depthBrace === 0
    ) {
      separatorIndex = index;
      break;
    }
  }

  if (separatorIndex < 0) {
    return undefined;
  }

  const keyText = entry.slice(0, separatorIndex).trim();

  if (/^["'][\s\S]*["']$/u.test(keyText)) {
    return {
      raw: keyText,
      normalized: keyText.slice(1, -1),
    };
  }

  if (/^-?\d+$/u.test(keyText)) {
    return {
      raw: keyText,
      normalized: keyText,
    };
  }

  if (/^[A-Za-z_][A-Za-z0-9_]*$/u.test(keyText)) {
    return {
      raw: keyText,
      normalized: keyText,
    };
  }

  return undefined;
}

function collectSwitchMultipleDefaultFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.switchMultipleDefault;
  const findings: ObservedFact[] = [];
  const switchPattern = /\bswitch\s*\(/gu;

  for (const switchMatch of findAllMatches(text, switchPattern)) {
    const openBrace = findSwitchOpenBrace(text, switchMatch.endOffset);

    if (openBrace < 0) {
      continue;
    }

    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');

    if (closeBrace < 0) {
      continue;
    }

    const body = text.slice(openBrace + 1, closeBrace);
    const defaultPattern = /^\s*default\s*:/gmu;
    let defaultCount = 0;

    for (const defaultMatch of body.matchAll(defaultPattern)) {
      const matchIndex = defaultMatch.index ?? 0;

      if (!isTopLevelSwitchDefault(body, matchIndex)) {
        continue;
      }

      defaultCount += 1;

      if (defaultCount > 1) {
        const absoluteStart = openBrace + 1 + matchIndex;
        const absoluteEnd = absoluteStart + defaultMatch[0].length;

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteEnd,
            text: defaultMatch[0].trim(),
          }),
        );
      }
    }
  }

  return findings;
}

function findSwitchOpenBrace(text: string, fromOffset: number): number {
  let depth = 1;

  for (let index = fromOffset; index < text.length; index += 1) {
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

function isTopLevelSwitchDefault(body: string, matchIndex: number): boolean {
  let depthBrace = 0;

  for (let index = 0; index < matchIndex; index += 1) {
    const char = body[index];

    if (char === '{') {
      depthBrace += 1;
      continue;
    }

    if (char === '}') {
      depthBrace = Math.max(0, depthBrace - 1);
    }
  }

  return depthBrace === 0;
}

function collectErrorSuppressionOperatorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.errorSuppressionOperator,
    appliesTo: 'block',
    pattern: /(?<![@\w])@(?=\s*(?:\$|[A-Za-z_(]|new\s))/gu,
  });
}

function collectUnreachableAfterReturnFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.unreachableAfterReturn;
  const findings: ObservedFact[] = [];
  const lines = text.split(/\r?\n/u);
  let offset = 0;
  let braceDepth = 0;
  let unreachableDepth: number | undefined;

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    const trimmed = line.trim();
    const lineStart = offset;
    const lineEnd = offset + line.length;

    if (unreachableDepth !== undefined && trimmed.length > 0) {
      const isClosingBraceOnly = trimmed === '}';
      const isComment =
        trimmed.startsWith('//') ||
        trimmed.startsWith('#') ||
        trimmed.startsWith('/*') ||
        trimmed.startsWith('*');

      if (
        !isClosingBraceOnly &&
        !isComment &&
        braceDepth >= unreachableDepth
      ) {
        const contentStart =
          lineStart + (line.length - line.trimStart().length);
        const contentEnd = lineEnd;

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: contentStart,
            endOffset: contentEnd,
            text: line.trimEnd(),
          }),
        );
      }
    }

    const terminalOnLine =
      /\b(?:return|throw)\b/u.test(line) && /;[\s]*$/u.test(trimmed);

    for (let index = 0; index < line.length; index += 1) {
      const char = line[index];

      if (char === '{') {
        braceDepth += 1;
      } else if (char === '}') {
        braceDepth = Math.max(0, braceDepth - 1);

        if (
          unreachableDepth !== undefined &&
          braceDepth < unreachableDepth
        ) {
          unreachableDepth = undefined;
        }
      }
    }

    if (terminalOnLine) {
      unreachableDepth = braceDepth;
    } else if (
      unreachableDepth !== undefined &&
      braceDepth < unreachableDepth
    ) {
      unreachableDepth = undefined;
    }

    offset = lineEnd;

    if (lineIndex < lines.length - 1) {
      const newline = text.slice(offset).match(/^(\r?\n)/u)?.[1] ?? '\n';
      offset += newline.length;
    }
  }

  return findings;
}

function collectNullsafeReturnedByReferenceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.nullsafeReturnedByReference,
    appliesTo: 'block',
    pattern:
      /\b(?:static\s+)?fn\s*&\s*\([^)]*\)\s*=>\s*[^;{}\n]*\?->/gu,
  });
}
