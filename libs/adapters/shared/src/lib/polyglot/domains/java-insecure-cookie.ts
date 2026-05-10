import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

const sessionLikeCookieNamePattern =
  /new\s+(?:[\w.]+\.)?Cookie\s*\(\s*["']([^"']*(?:session|jsession|auth|token|jwt|refresh)[^"']*)["']/i;

export interface JavaInsecureCookieOptions<TState> {
  detector: string;
  matchesTainted: (text: string, state: TState) => boolean;
  state: TState;
  text: string;
}

export function collectJavaInsecureCookieFacts<TState>(
  options: JavaInsecureCookieOptions<TState>,
): ObservedFact[] {
  const explicitWeakFlags = collectMatchedFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.servlet-insecure-cookie',
    pattern: /\.(?:httpOnly|secure)\s*\(\s*false\s*\)/g,
    appliesTo: 'block',
    props: ({ matchedText }) => ({
      pattern: 'explicit-insecure-flag',
      detail: matchedText.trim(),
    }),
    textValue: ({ matchedText }) => matchedText.trim(),
  });

  const weakSessionCookies = collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.servlet-insecure-cookie',
    pattern: /\bnew\s+(?:[\w.]+\.)?Cookie\s*\(/g,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet, state) =>
      sessionLikeCookieNamePattern.test(snippet.text) ||
      options.matchesTainted(snippet.text, state),
    props: () => ({ pattern: 'session-or-tainted-cookie' }),
  });

  return [...explicitWeakFlags, ...weakSessionCookies];
}
