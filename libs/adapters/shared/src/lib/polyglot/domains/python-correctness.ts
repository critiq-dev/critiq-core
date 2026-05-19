import type { ObservedFact } from '@critiq/core-rules-engine';

import { createOffsetFact } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const PYTHON_CORRECTNESS_FACT_KINDS = {
  bareExcept: 'python.correctness.bare-except',
  dangerousMutableDefault: 'python.correctness.dangerous-mutable-default',
  broadExceptionHandler: 'python.correctness.broad-exception-handler',
  duplicateDictKey: 'python.correctness.duplicate-dict-key',
  assertOnTuple: 'python.correctness.assert-on-tuple',
} as const;

export interface CollectPythonCorrectnessFactsOptions {
  text: string;
  detector: string;
}

export function collectPythonCorrectnessFacts(
  options: CollectPythonCorrectnessFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectBareExceptFacts(text, detector),
    ...collectDangerousMutableDefaultFacts(text, detector),
    ...collectBroadExceptionHandlerFacts(text, detector),
    ...collectDuplicateDictKeyFacts(text, detector),
    ...collectAssertOnTupleFacts(text, detector),
  ];
}

function collectBareExceptFacts(text: string, detector: string): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CORRECTNESS_FACT_KINDS.bareExcept,
    appliesTo: 'block',
    pattern: /^\s*except\s*:\s*(?:#.*)?$/gm,
  });
}

function collectDangerousMutableDefaultFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CORRECTNESS_FACT_KINDS.dangerousMutableDefault,
    appliesTo: 'block',
    pattern:
      /^\s*def\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*=\s*(?:\[[^\]]*\]|\{[^}]*\}|set\s*\(\s*\))[^)]*\)\s*:/gm,
  });
}

function collectBroadExceptionHandlerFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CORRECTNESS_FACT_KINDS.broadExceptionHandler,
    appliesTo: 'block',
    pattern:
      /^\s*except\s+(?:Exception|BaseException)\b(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*:/gm,
  });
}

function collectDuplicateDictKeyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PYTHON_CORRECTNESS_FACT_KINDS.duplicateDictKey;
  const literals = collectDictLiteralRanges(text);
  const findings: ObservedFact[] = [];

  for (const literal of literals) {
    const seen = new Set<string>();
    const entries = splitTopLevelEntries(literal.content);

    for (const entry of entries) {
      const key = extractStaticDictKey(entry.text);

      if (!key) {
        continue;
      }

      if (seen.has(key.normalized)) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: literal.startOffset + 1 + entry.startOffset,
            endOffset:
              literal.startOffset + 1 + entry.startOffset + key.raw.length,
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

function collectAssertOnTupleFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_CORRECTNESS_FACT_KINDS.assertOnTuple,
    appliesTo: 'block',
    pattern:
      /^\s*assert\s*\(\s*[A-Za-z_][A-Za-z0-9_.'"[\]\s+\-*/%]*\s*,\s*[^)\n]+\)\s*$/gm,
  });
}

interface DictLiteralRange {
  startOffset: number;
  endOffset: number;
  content: string;
}

function collectDictLiteralRanges(text: string): DictLiteralRange[] {
  const ranges: DictLiteralRange[] = [];
  const stack: number[] = [];

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];

    if (char === '{') {
      stack.push(index);
      continue;
    }

    if (char !== '}' || stack.length === 0) {
      continue;
    }

    const start = stack.pop();

    if (start === undefined) {
      continue;
    }

    const content = text.slice(start + 1, index);

    if (!hasTopLevelColon(content)) {
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

function hasTopLevelColon(source: string): boolean {
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

    if (char === ':' && depthParen === 0 && depthBracket === 0 && depthBrace === 0) {
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

interface StaticDictKey {
  raw: string;
  normalized: string;
}

function extractStaticDictKey(entry: string): StaticDictKey | undefined {
  if (entry.startsWith('**')) {
    return undefined;
  }

  let depthParen = 0;
  let depthBracket = 0;
  let depthBrace = 0;
  let separatorIndex = -1;

  for (let index = 0; index < entry.length; index += 1) {
    const char = entry[index];

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

    if (char === ':' && depthParen === 0 && depthBracket === 0 && depthBrace === 0) {
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

  if (/^-?\d+(?:\.\d+)?$/u.test(keyText)) {
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
