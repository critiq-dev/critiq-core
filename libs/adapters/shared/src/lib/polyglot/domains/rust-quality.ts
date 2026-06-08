import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches } from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const RUST_QUALITY_FACT_KINDS = {
  potentiallyIncompleteAsciiRange: 'rust.quality.potentially-incomplete-ascii-range',
  inaccurateDurationCalculation: 'rust.quality.inaccurate-duration-calculation',
  mapFollowedByCount: 'rust.quality.map-followed-by-count',
  iterNthInsteadOfGet: 'rust.quality.iter-nth-instead-of-get',
  iterCountInsteadOfLen: 'rust.quality.iter-count-instead-of-len',
  replaceSamePatternAndReplacement: 'rust.quality.replace-same-pattern-and-replacement',
  cloneOnDoubleReference: 'rust.quality.clone-on-double-reference',
  nonOwnedRcPointerIntoVec: 'rust.quality.non-owned-rc-pointer-into-vec',
} as const;

export interface CollectRustQualityFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectRustQualityFacts(
  options: CollectRustQualityFactsOptions,
): ObservedFact[] {
  const { text, detector, path } = options;

  if (path && isRustQualitySuppressedPath(path)) {
    return [];
  }

  return dedupeFacts([
    ...collectPotentiallyIncompleteAsciiRangeFacts(text, detector),
    ...collectInaccurateDurationCalculationFacts(text, detector),
    ...collectMapFollowedByCountFacts(text, detector),
    ...collectIterNthInsteadOfGetFacts(text, detector),
    ...collectIterCountInsteadOfLenFacts(text, detector),
    ...collectReplaceSamePatternAndReplacementFacts(text, detector),
    ...collectCloneOnDoubleReferenceFacts(text, detector),
    ...collectNonOwnedRcPointerIntoVecFacts(text, detector),
  ]);
}

function isRustQualitySuppressedPath(path: string): boolean {
  return (
    /(^|\/)tests?(\/|$)/u.test(path) ||
    /(^|\/)testdata(\/|$)/u.test(path) ||
    /(^|\/)examples?(\/|$)/u.test(path) ||
    /(^|\/)benches?(\/|$)/u.test(path) ||
    /_test\.rs$/u.test(path) ||
    /\.spec\.rs$/u.test(path)
  );
}

/**
 * Flags exclusive range `'a'..'z'` where inclusive `..=` is likely intended.
 * RS-W1086
 */
function collectPotentiallyIncompleteAsciiRangeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.potentiallyIncompleteAsciiRange;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /'[a-zA-Z0-9]'\s*\.\.\s*'[a-zA-Z0-9]'/gu,
    predicate: (match) => {
      const after = text.slice(match.endOffset);
      return !after.startsWith('=');
    },
  });
}

/**
 * Flags `subsec_micros() / 1_000` or `subsec_nanos() / 1_000` instead of
 * using `subsec_millis()` / `subsec_micros()` directly. RS-W1087
 */
function collectInaccurateDurationCalculationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.inaccurateDurationCalculation;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\b(?:\.subsec_micros\s*\(\s*\)\s*\/\s*1_000|\.subsec_nanos\s*\(\s*\)\s*\/\s*1_000)/gu,
  });
}

/**
 * Flags `.map(...).count()` where the map does not affect the count. RS-W1089
 */
function collectMapFollowedByCountFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_QUALITY_FACT_KINDS.mapFollowedByCount,
    appliesTo: 'block',
    pattern: /\.map\s*\([^)]*\)\s*\.count\s*\(\s*\)/gu,
  });
}

/**
 * Flags `.iter().nth(idx)` or `.iter_mut().nth(idx)` instead of directly
 * indexing with `.get()` / `.get_mut()`. RS-W1091
 */
function collectIterNthInsteadOfGetFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_QUALITY_FACT_KINDS.iterNthInsteadOfGet,
    appliesTo: 'block',
    pattern: /\.iter(?:_mut)?\s*\(\s*\)\s*\.nth\s*\(/gu,
  });
}

/**
 * Flags `.iter().count()` where `.len()` is more efficient. RS-W1093
 */
function collectIterCountInsteadOfLenFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_QUALITY_FACT_KINDS.iterCountInsteadOfLen,
    appliesTo: 'block',
    pattern: /\.iter\s*\(\s*\)\s*\.count\s*\(\s*\)/gu,
  });
}

/**
 * Flags `.replace()` or `.replacen()` where pattern and replacement are the
 * same string (no-op). RS-W1094
 */
function collectReplaceSamePatternAndReplacementFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.replaceSamePatternAndReplacement;
  const findings: ObservedFact[] = [];

  const pattern = /\.(?:replacen?)\s*\(\s*("[^"]*"|'[^']*')\s*,\s*\1/gu;

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
 * Flags `.clone()` on a double reference inside closure patterns. RS-W1100
 */
function collectCloneOnDoubleReferenceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.cloneOnDoubleReference;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\|\s*[A-Za-z_][A-Za-z0-9_]*\s*\|[^|{}]*\.clone\s*\(\s*\)/gu,
    predicate: (match) => !match.matchedText.includes('(*'),
  });
}

/**
 * Flags non-owned Rc pointer cloned and pushed into a vector. RS-W1106
 */
function collectNonOwnedRcPointerIntoVecFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.nonOwnedRcPointerIntoVec;
  const findings: ObservedFact[] = [];

  const pattern = /Rc::new\s*\([^)]+\)/gu;

  for (const rcMatch of findAllMatches(text, pattern)) {
    const afterRc = text.slice(rcMatch.endOffset);
    const pushPattern = /\.(?:push|insert)\s*\(\s*[^)]*\.clone\s*\(\s*\)/gu;

    const pushMatch = pushPattern.exec(afterRc);
    if (pushMatch) {
      const absoluteStart = rcMatch.startOffset;
      const absoluteEnd = rcMatch.endOffset + pushMatch.index + pushMatch[0].length;

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
  }

  return findings;
}
