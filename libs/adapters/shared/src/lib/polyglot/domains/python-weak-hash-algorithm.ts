import type { ObservedFact } from '@critiq/core-rules-engine';

import type { CallSnippet } from '../../runtime';
import { collectSnippetFacts } from './collect-snippet-facts';

const emptySnippetState: Record<string, never> = {};

const CHECKSUM_CONTEXT_PATTERN =
  /\b(?:checksum|content_?hash|digest|etag|file_?hash|md5sum|non_?security|sha1?sum)\b/i;
const SECURITY_CONTEXT_PATTERN =
  /\b(?:auth|cookie|hmac|itsdangerous|jwt|password|salt|secret|session|sign|signature|serializer|token)\b/i;
const COMPAT_COMMENT_PATTERN = /#\s*critiq:compat\b/i;

export interface CollectPythonWeakHashFactsOptions {
  text: string;
  detector: string;
}

export function collectPythonWeakHashFacts(
  options: CollectPythonWeakHashFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectSnippetFacts({
      text,
      detector,
      kind: 'security.weak-hash-algorithm',
      appliesTo: 'block',
      pattern: /\bhashlib\.(?:md5|sha1)\s*\(/g,
      state: emptySnippetState,
      predicate: (snippet) =>
        shouldFlagPythonWeakHash(text, snippet) &&
        !isChecksumOnlyContext(text, snippet),
    }),
    ...collectSnippetFacts({
      text,
      detector,
      kind: 'security.weak-hash-algorithm',
      appliesTo: 'block',
      pattern: /\bhmac\.new\s*\(/g,
      state: emptySnippetState,
      predicate: (snippet) =>
        isWeakHmacDigest(snippet.text) && !isChecksumOnlyContext(text, snippet),
    }),
  ];
}

function extractContextWindow(
  text: string,
  startOffset: number,
  before = 700,
): string {
  return text.slice(Math.max(0, startOffset - before), startOffset);
}

function isWeakHmacDigest(snippetText: string): boolean {
  return (
    /\bdigestmod\s*=\s*(?:hashlib\.)?(?:md5|sha1)\b/u.test(snippetText) ||
    /,\s*(?:hashlib\.)?(?:md5|sha1)\s*(?:[,)])/u.test(snippetText)
  );
}

function isChecksumOnlyContext(text: string, snippet: CallSnippet): boolean {
  const window = `${extractContextWindow(text, snippet.startOffset)}${snippet.text}`;

  if (COMPAT_COMMENT_PATTERN.test(window)) {
    return true;
  }

  if (/\bdef\s+(?:checksum|digest|etag|fingerprint)\s*\(/iu.test(window)) {
    return true;
  }

  return (
    CHECKSUM_CONTEXT_PATTERN.test(window) && !SECURITY_CONTEXT_PATTERN.test(window)
  );
}

function shouldFlagPythonWeakHash(text: string, snippet: CallSnippet): boolean {
  const window = `${extractContextWindow(text, snippet.startOffset)}${snippet.text}`;

  return SECURITY_CONTEXT_PATTERN.test(window);
}
