import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches } from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const RUBY_PERFORMANCE_FACT_KINDS = {
  noStaticSizeComputation: 'ruby.performance.no-static-size-computation',
  preferFlatMap: 'ruby.performance.prefer-flat-map',
  efficientHashSearch: 'ruby.performance.efficient-hash-search',
  preferStructOverOpenStruct: 'ruby.performance.prefer-struct-over-openstruct',
  rangeCoverOverInclude: 'ruby.performance.range-cover-over-include',
  yieldOverBlockCall: 'ruby.performance.yield-over-block-call',
  regexMatchOverMatch: 'ruby.performance.regex-match-over-match',
  mergeSingleKey: 'ruby.performance.merge-single-key',
  enumerableIndexBy: 'ruby.performance.enumerable-index-by',
  enumerableIndexWith: 'ruby.performance.enumerable-index-with',
  preferDeletePrefix: 'ruby.performance.prefer-delete-prefix',
  preferDeleteSuffix: 'ruby.performance.prefer-delete-suffix',
} as const;

export function collectRubySpecificPerformanceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return dedupeFacts([
    ...collectRubyNoStaticSizeComputationFacts(text, detector),
    ...collectRubyPreferFlatMapFacts(text, detector),
    ...collectRubyEfficientHashSearchFacts(text, detector),
    ...collectRubyPreferStructOverOpenStructFacts(text, detector),
    ...collectRubyRangeCoverOverIncludeFacts(text, detector),
    ...collectRubyYieldOverBlockCallFacts(text, detector),
    ...collectRubyRegexMatchOverMatchFacts(text, detector),
    ...collectRubyMergeSingleKeyFacts(text, detector),
    ...collectRubyEnumerableIndexByFacts(text, detector),
    ...collectRubyEnumerableIndexWithFacts(text, detector),
    ...collectRubyPreferDeletePrefixFacts(text, detector),
    ...collectRubyPreferDeleteSuffixFacts(text, detector),
  ]);
}

function collectRubyNoStaticSizeComputationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_PERFORMANCE_FACT_KINDS.noStaticSizeComputation;
  const findings: ObservedFact[] = [];

  const arrayPattern =
    /\[(?:[^[\]#{'")]|"[^"]*"|'[^']*')*\]\.(?:count|size|length)\b/g;
  const hashPattern =
    /\{[^{}#]*\}\.(?:count|size|length)\b/g;

  for (const match of findAllMatches(text, arrayPattern)) {
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

  for (const match of findAllMatches(text, hashPattern)) {
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

function collectRubyPreferFlatMapFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_PERFORMANCE_FACT_KINDS.preferFlatMap,
    pattern: /\.map\s*\{[^}]*\}\s*\.flatten\b/g,
    appliesTo: 'block',
  });
}

function collectRubyEfficientHashSearchFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: RUBY_PERFORMANCE_FACT_KINDS.efficientHashSearch,
      pattern: /\.keys\s*\.\s*include\?\s*\(/g,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: RUBY_PERFORMANCE_FACT_KINDS.efficientHashSearch,
      pattern: /\.values\s*\.\s*include\?\s*\(/g,
      appliesTo: 'block',
    }),
  ];
}

function collectRubyPreferStructOverOpenStructFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_PERFORMANCE_FACT_KINDS.preferStructOverOpenStruct,
    pattern: /\bOpenStruct\.new\b/g,
    appliesTo: 'block',
  });
}

function collectRubyRangeCoverOverIncludeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: RUBY_PERFORMANCE_FACT_KINDS.rangeCoverOverInclude,
      pattern: /\([^)]+\.\.[^)]+\)\.include\?/g,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: RUBY_PERFORMANCE_FACT_KINDS.rangeCoverOverInclude,
      pattern: /\([^)]+\.\.\.[^)]+\)\.include\?/g,
      appliesTo: 'block',
    }),
  ];
}

function collectRubyYieldOverBlockCallFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_PERFORMANCE_FACT_KINDS.yieldOverBlockCall,
    pattern: /\bdef\s+\w+[\s\S]*?&\s*(\w+)[\s\S]*?\1\.call\b/g,
    appliesTo: 'block',
  });
}

function collectRubyRegexMatchOverMatchFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_PERFORMANCE_FACT_KINDS.regexMatchOverMatch;
  const findings: ObservedFact[] = [];

  const pattern =
    /(?:if|unless|while|until)\s+[^=]*?\.match\s*\(/g;

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

function collectRubyMergeSingleKeyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_PERFORMANCE_FACT_KINDS.mergeSingleKey;
  const findings: ObservedFact[] = [];
  const seen = new Set<number>();

  const parenPattern = /\.merge!\s*\([^)]*\)/g;
  const noParenPattern = /\.merge!\s+(?:\w+:\s*[^,)]+)/g;

  for (const match of findAllMatches(text, parenPattern)) {
    const call = match.matchedText;
    const openParen = call.indexOf('(');
    const closeParen = call.lastIndexOf(')');
    const args = call.slice(openParen + 1, closeParen).trim();

    if (args.startsWith('{') && args.endsWith('}')) {
      const hashContent = args.slice(1, -1).trim();
      if (!hashContent) continue;

      const commaCount = countTopLevelCommas(hashContent);
      if (commaCount === 0) {
        seen.add(match.startOffset);
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: match.startOffset,
            endOffset: match.endOffset,
            text: call,
          }),
        );
      }
    } else if (args.includes(':') && !args.includes(',')) {
      seen.add(match.startOffset);
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: call,
        }),
      );
    }
  }

  for (const match of findAllMatches(text, noParenPattern)) {
    if (seen.has(match.startOffset)) continue;
    const call = match.matchedText;
    const argPart = call.replace(/^.*?\.merge!\s+/, '');
    if (!argPart.includes(',')) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: call,
        }),
      );
    }
  }

  return findings;
}

function countTopLevelCommas(s: string): number {
  let count = 0;
  let depth = 0;
  let inString = false;
  let stringChar = '';

  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inString) {
      if (ch === '\\') { i += 1; continue; }
      if (ch === stringChar) inString = false;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inString = true;
      stringChar = ch;
      continue;
    }
    if (ch === '(' || ch === '{' || ch === '[') { depth++; continue; }
    if (ch === ')' || ch === '}' || ch === ']') { depth--; continue; }
    if (ch === ',' && depth === 0) count++;
  }
  return count;
}

function collectRubyEnumerableIndexByFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_PERFORMANCE_FACT_KINDS.enumerableIndexBy,
    appliesTo: 'block',
    pattern: /\.map\s*\{[^}]*\}\.to_h\b/g,
    predicate: (match) => {
      const blockText = match.matchedText;
      const arrowIdx = blockText.indexOf('|');
      if (arrowIdx === -1) return false;
      const afterPipe = blockText.indexOf('|', arrowIdx + 1);
      if (afterPipe === -1) return false;
      const params = blockText.slice(arrowIdx + 1, afterPipe).trim();
      if (!params) return false;
      const firstParam = params.split(',')[0].trim();
      const body = blockText.slice(afterPipe + 1, blockText.lastIndexOf('}')).trim();
      const keyThenElement = new RegExp(`\\[\\s*\\b${escapeRegExp(firstParam)}\\.[^\\]]*\\s*,\\s*\\b${escapeRegExp(firstParam)}\\s*\\]`);
      const keyThenElementHash = new RegExp(`\\[\\s*\\b${escapeRegExp(firstParam)}\\[[^\\]]*\\]\\s*,\\s*\\b${escapeRegExp(firstParam)}\\s*\\]`);
      return keyThenElement.test(body) || keyThenElementHash.test(body);
    },
  });
}

function collectRubyEnumerableIndexWithFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_PERFORMANCE_FACT_KINDS.enumerableIndexWith,
    appliesTo: 'block',
    pattern: /\.map\s*\{[^}]*\}\.to_h\b/g,
    predicate: (match) => {
      const blockText = match.matchedText;
      const arrowIdx = blockText.indexOf('|');
      if (arrowIdx === -1) return false;
      const afterPipe = blockText.indexOf('|', arrowIdx + 1);
      if (afterPipe === -1) return false;
      const params = blockText.slice(arrowIdx + 1, afterPipe).trim();
      if (!params) return false;
      const firstParam = params.split(',')[0].trim();
      const body = blockText.slice(afterPipe + 1, blockText.lastIndexOf('}')).trim();
      const elementThenValue = new RegExp(`\\[\\s*\\b${escapeRegExp(firstParam)}\\s*,\\s*\\b${escapeRegExp(firstParam)}\\.[^\\]]*\\s*\\]`);
      const elementThenValueHash = new RegExp(`\\[\\s*\\b${escapeRegExp(firstParam)}\\s*,\\s*\\b${escapeRegExp(firstParam)}\\[[^\\]]*\\]\\s*\\]`);
      return elementThenValue.test(body) || elementThenValueHash.test(body);
    },
  });
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function collectRubyPreferDeletePrefixFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_PERFORMANCE_FACT_KINDS.preferDeletePrefix,
    appliesTo: 'block',
    pattern: /\b(?:sub|gsub)\s*\(\s*\/\\A[^/]*\/[imxo]*\s*,\s*(?:''|"")\s*\)/g,
  });
}

function collectRubyPreferDeleteSuffixFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_PERFORMANCE_FACT_KINDS.preferDeleteSuffix,
    appliesTo: 'block',
    pattern: /\b(?:sub|gsub)\s*\(\s*\/[^/]*\\z\/[imxo]*\s*,\s*(?:''|"")\s*\)/g,
  });
}
