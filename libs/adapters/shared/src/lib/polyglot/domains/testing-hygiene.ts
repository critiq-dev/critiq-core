import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  isTestLikeSourcePath,
  TICKET_OR_SUPPRESSION_PATTERN,
} from '../../testing-paths';
import { createOffsetFact } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { findMatchingDelimiter } from '../../runtime';

const E2E_OR_INTEGRATION_PATH = /(?:^|\/)(?:e2e|integration)(?:\/|$)|[._]integration[._]/i;

export function isNarrowUnitTestPath(path: string): boolean {
  return isTestLikeSourcePath(path) && !E2E_OR_INTEGRATION_PATH.test(path);
}

function lineContextHasTicket(text: string, startOffset: number): boolean {
  const before = text.slice(0, startOffset);
  const lines = before.split(/\r?\n/);
  const prevLine = lines.length >= 2 ? (lines[lines.length - 2] ?? '') : '';
  const sameLinePrefix = lines[lines.length - 1] ?? '';
  const restOfLine = text.slice(startOffset).split(/\r?\n/, 1)[0] ?? '';
  const combined = `${prevLine}\n${sameLinePrefix}`;

  return (
    TICKET_OR_SUPPRESSION_PATTERN.test(combined) ||
    TICKET_OR_SUPPRESSION_PATTERN.test(restOfLine)
  );
}

export interface PolyglotTestingPathOptions {
  text: string;
  path: string;
  detector: string;
}

export function collectGoTestingHygieneFacts(
  options: PolyglotTestingPathOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  if (!isNarrowUnitTestPath(path) || !path.endsWith('_test.go')) {
    return [];
  }

  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'go.testing.t-skip-without-ticket-reference',
      pattern: /\bt\.Skip(?:f)?\s*\(/g,
      appliesTo: 'block',
      predicate: (match) => !lineContextHasTicket(text, match.startOffset),
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'go.testing.time-sleep-in-unit-test',
      pattern: /\btime\.Sleep\s*\(/g,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'go.testing.real-network-in-unit-test',
      pattern:
        /\b(?:http\.(?:Get|Head|Post|PostForm)|http\.Client\b|net\.Dial(?:TCP)?\s*\()/g,
      appliesTo: 'block',
    }),
  ];
}

export function collectPythonTestingHygieneFacts(
  options: PolyglotTestingPathOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  if (!isNarrowUnitTestPath(path) || !/\.py$/i.test(path)) {
    return [];
  }

  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'py.testing.pytest-skip-without-ticket-reference',
      pattern: /@pytest\.mark\.skip\b/g,
      appliesTo: 'block',
      predicate: (match) => {
        const rest = text.slice(
          match.startOffset,
          Math.min(text.length, match.startOffset + 240),
        );
        if (/\breason\s*=/.test(rest)) {
          return false;
        }
        return !lineContextHasTicket(text, match.startOffset);
      },
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'py.testing.real-network-in-unit-test',
      pattern:
        /\b(?:requests\.(?:get|post|put|patch|delete|head|options)|httpx\.(?:get|post|put|patch|delete|head|options)|urllib\.request\.urlopen)\s*\(/g,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'py.testing.time-sleep-in-unit-test',
      pattern: /\btime\.sleep\s*\(/g,
      appliesTo: 'block',
    }),
  ];
}

export function collectRubyTestingHygieneFacts(
  options: PolyglotTestingPathOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  if (!isNarrowUnitTestPath(path) || !/\.rb$/i.test(path)) {
    return [];
  }

  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'ruby.testing.focused-example',
      pattern: /\b(?:fit|fdescribe)\b/g,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'ruby.testing.skip-without-ticket-reference',
      pattern: /\bskip\s*\(/g,
      appliesTo: 'block',
      predicate: (match) => !lineContextHasTicket(text, match.startOffset),
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'ruby.testing.pending-without-ticket-reference',
      pattern: /\bpending\b/g,
      appliesTo: 'block',
      predicate: (match) => !lineContextHasTicket(text, match.startOffset),
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'ruby.testing.real-network-in-unit-test',
      pattern: /\b(?:Net::HTTP|Faraday|HTTParty)\b/g,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'ruby.testing.sleep-in-unit-test',
      pattern: /\bsleep\s*\(/g,
      appliesTo: 'block',
    }),
  ];
}

export function collectRustTestingHygieneFacts(
  options: PolyglotTestingPathOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  if (!isNarrowUnitTestPath(path) || !/\.rs$/i.test(path)) {
    return [];
  }

  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'rust.testing.ignore-without-ticket-reference',
      pattern: /#\[\s*ignore\s*\]/g,
      appliesTo: 'block',
      predicate: (match) => {
        const ctx = text.slice(Math.max(0, match.startOffset - 120), match.startOffset);
        return !TICKET_OR_SUPPRESSION_PATTERN.test(ctx);
      },
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'rust.testing.real-network-in-unit-test',
      pattern: /\breqwest::/g,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'rust.testing.thread-sleep-in-unit-test',
      pattern: /\b(?:std::thread::sleep|tokio::time::sleep)\s*\(/g,
      appliesTo: 'block',
    }),
  ];
}

export function collectJavaTestingHygieneFacts(
  options: PolyglotTestingPathOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  if (!isNarrowUnitTestPath(path) && !/Test\.java$/i.test(path)) {
    return [];
  }

  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'java.testing.disabled-without-ticket-reference',
      pattern: /@Disabled\b(?:\s*\(\s*\))?/g,
      appliesTo: 'block',
      predicate: (match) => {
        const snippet = text.slice(
          match.startOffset,
          Math.min(text.length, match.endOffset + 120),
        );
        if (/@Disabled\s*\(\s*["'][^"']{2,}["']/.test(snippet)) {
          return false;
        }
        if (/value\s*=\s*"/.test(snippet) && TICKET_OR_SUPPRESSION_PATTERN.test(snippet)) {
          return false;
        }
        return !lineContextHasTicket(text, match.startOffset);
      },
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'java.testing.thread-sleep-in-unit-test',
      pattern: /\bThread\.sleep\s*\(/g,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'java.testing.http-client-in-unit-test',
      pattern:
        /\b(?:HttpClient\.newHttpClient|new\s+URL\s*\(|HttpURLConnection|RestTemplate)\b/g,
      appliesTo: 'block',
    }),
    ...collectSetupTeardownAnnotationFacts(text, detector),
    ...collectSetupWithoutSuperFacts(text, detector),
    ...collectTeardownWithoutSuperFacts(text, detector),
  ];
}

function collectSetupTeardownAnnotationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = 'java.testing.setup-teardown-annotation';

  const methodPattern =
    /(?:(?:public|protected|private)\s+)?void\s+(setUp|tearDown)\s*\(\s*\)/gu;
  for (const match of text.matchAll(methodPattern)) {
    const methodName = match[1];
    if (!methodName) continue;
    const matchedText = match[0];
    const startOffset = match.index ?? 0;
    const endOffset = startOffset + matchedText.length;
    const lineStart = text.lastIndexOf('\n', startOffset) + 1;
    const beforeMethod = text.slice(Math.max(0, lineStart - 200), lineStart);

    const hasAnnotation =
      /@(?:Override|Before|BeforeEach|After|AfterEach)/.test(beforeMethod) ||
      /@(?:Override|Before|BeforeEach|After|AfterEach)/.test(
        text.slice(text.lastIndexOf('\n', Math.max(0, lineStart - 2)) + 1, lineStart),
      );

    if (hasAnnotation) continue;

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset,
        endOffset,
        text: matchedText,
      }),
    );
  }

  return findings;
}

export function collectSetupWithoutSuperFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = 'java.testing.setup-without-super';

  const methodPattern = /(?:(?:public|protected|private)\s+)?void\s+setUp\s*\(\s*\)/gu;
  for (const match of text.matchAll(methodPattern)) {
    const startOffset = match.index!;
    const endOffset = startOffset + match[0].length;
    const braceStart = text.indexOf('{', endOffset);
    if (braceStart < 0) continue;
    const methodBody = text.slice(endOffset, braceStart);
    const bodyStart = braceStart + 1;
    const blockEnd = findMatchingDelimiter(text, braceStart, '{', '}');
    if (blockEnd < 0) continue;
    const body = text.slice(bodyStart, blockEnd);
    if (/\bsuper\s*\.\s*setUp\s*\(\s*\)/.test(body)) continue;
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset,
        endOffset,
        text: match[0],
      }),
    );
  }

  return findings;
}

export function collectTeardownWithoutSuperFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = 'java.testing.teardown-without-super';

  const methodPattern = /(?:(?:public|protected|private)\s+)?void\s+tearDown\s*\(\s*\)/gu;
  for (const match of text.matchAll(methodPattern)) {
    const startOffset = match.index!;
    const endOffset = startOffset + match[0].length;
    const braceStart = text.indexOf('{', endOffset);
    if (braceStart < 0) continue;
    const bodyStart = braceStart + 1;
    const blockEnd = findMatchingDelimiter(text, braceStart, '{', '}');
    if (blockEnd < 0) continue;
    const body = text.slice(bodyStart, blockEnd);
    if (/\bsuper\s*\.\s*tearDown\s*\(\s*\)/.test(body)) continue;
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset,
        endOffset,
        text: match[0],
      }),
    );
  }

  return findings;
}

export function collectPhpTestingHygieneFacts(
  options: PolyglotTestingPathOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  if (!isNarrowUnitTestPath(path) || !/\.php$/i.test(path)) {
    return [];
  }

  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'php.testing.mark-test-skipped-without-ticket-reference',
      pattern: /\bmarkTestSkipped\s*\(\s*\)/g,
      appliesTo: 'block',
      predicate: (match) => !lineContextHasTicket(text, match.startOffset),
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'php.testing.sleep-in-unit-test',
      pattern: /\bsleep\s*\(/g,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: 'php.testing.curl-in-unit-test',
      pattern: /\bcurl_(?:exec|init)\s*\(/g,
      appliesTo: 'block',
    }),
  ];
}
