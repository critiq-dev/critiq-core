import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches } from '../../runtime';
import { stripHashLineComment } from '../text';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

export const RUBY_BUG_RISK_FACT_KINDS = {
  exceptionClassOverwritten: 'ruby.bug-risk.exception-class-overwritten',
  rawSqlWithoutSquish: 'ruby.bug-risk.raw-sql-without-squish',
  divisionByZero: 'ruby.bug-risk.division-by-zero',
  assignmentInCondition: 'ruby.bug-risk.assignment-in-condition',
  duplicateHashKeys: 'ruby.bug-risk.duplicate-hash-keys',
  deprecatedUriEscape: 'ruby.bug-risk.deprecated-uri-escape',
} as const;

const RESCUE_EXCEPTION_CLASS_NAMES =
  'StandardError|Exception|RuntimeError|ArgumentError|NameError|TypeError|NoMethodError|IOError|IndexError|RangeError|RegexpError|SyntaxError|LoadError|ZeroDivisionError|NotImplementedError|ScriptError|SecurityError|SystemCallError|SystemStackError|ThreadError|FrozenError|LocalJumpError';

export interface CollectRubyBugRiskFactsOptions {
  text: string;
  detector: string;
}

export function collectRubyBugRiskFacts(
  options: CollectRubyBugRiskFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return dedupeFacts([
    ...collectExceptionClassOverwrittenFacts(text, detector),
    ...collectRawSqlWithoutSquishFacts(text, detector),
    ...collectDivisionByZeroFacts(text, detector),
    ...collectAssignmentInConditionFacts(text, detector),
    ...collectDuplicateHashKeyFacts(text, detector),
    ...collectDeprecatedUriEscapeFacts(text, detector),
  ]);
}

function collectExceptionClassOverwrittenFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.exceptionClassOverwritten,
    appliesTo: 'block',
    pattern: new RegExp(
      `\\brescue\\s*=>\\s*(?:${RESCUE_EXCEPTION_CLASS_NAMES})\\b`,
      'g',
    ),
  });
}

function collectRawSqlWithoutSquishFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.rawSqlWithoutSquish;
  const callPatterns = [/\bwhere\s*\(/g, /\bfind_by_sql\s*\(/g];

  return callPatterns.flatMap((pattern) =>
    collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern,
      state: undefined,
      predicate: (snippet) => {
        if (!/<<-?~?\w*/u.test(snippet.text)) {
          return false;
        }

        return !/\.squish\b/u.test(snippet.text);
      },
    }),
  );
}

function collectDivisionByZeroFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.divisionByZero;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const pattern = /\/\s*0(?:\.0+)?\b/g;

    for (const match of findAllMatches(stripped, pattern)) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: offset + match.startOffset,
          endOffset: offset + match.endOffset,
          text: match.matchedText,
        }),
      );
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectAssignmentInConditionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.assignmentInCondition;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\b(?:if|unless|while|until)\s+(?:\([^)]*\s*)?(\w+)\s*=(?!=)(?![=>])/g,
  });
}

function collectDeprecatedUriEscapeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.deprecatedUriEscape,
    appliesTo: 'block',
    pattern: /\bURI\.(?:escape|unescape|encode|decode)\s*\(/g,
  });
}

function collectDuplicateHashKeyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.duplicateHashKeys;
  const findings: ObservedFact[] = [];

  for (const literal of collectRubyHashLiteralRanges(text)) {
    const seen = new Set<string>();

    for (const key of extractRubyHashKeys(literal.content)) {
      if (seen.has(key.normalized)) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: literal.startOffset + key.startOffset,
            endOffset: literal.startOffset + key.endOffset,
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

interface HashLiteralRange {
  startOffset: number;
  endOffset: number;
  content: string;
}

interface HashKeyMatch {
  raw: string;
  normalized: string;
  startOffset: number;
  endOffset: number;
}

function collectRubyHashLiteralRanges(text: string): HashLiteralRange[] {
  const ranges: HashLiteralRange[] = [];
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
    if (!looksLikeRubyHashLiteral(content)) {
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

function looksLikeRubyHashLiteral(content: string): boolean {
  return /:\w+\s*=>|["'][\w-]+["']\s*=>|\b\w+\s*:/u.test(content);
}

function extractRubyHashKeys(hashContent: string): HashKeyMatch[] {
  const keys: HashKeyMatch[] = [];

  for (const match of hashContent.matchAll(
    /(?:(["'])([^"']+)\1\s*=>)|(?::(\w+)\s*=>)|(?:\b(\w+)\s*:)/gu,
  )) {
    const symbol = match[2] ?? match[3] ?? match[4];
    if (!symbol) {
      continue;
    }

    const raw = match[0];
    const startOffset = match.index ?? 0;

    keys.push({
      raw,
      normalized: symbol.toLowerCase(),
      startOffset,
      endOffset: startOffset + raw.length,
    });
  }

  return keys;
}
