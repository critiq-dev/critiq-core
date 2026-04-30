import type { ObservedFact } from '@critiq/core-rules-engine';

import { type CallSnippet } from '../../runtime';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

export interface TlsSnippetPattern<TState> {
  pattern: RegExp;
  predicate?: (snippet: CallSnippet, state: TState) => boolean;
}

export interface TlsMatchPattern {
  pattern: RegExp;
}

export interface TlsVerificationDisabledOptions<TState> {
  detector: string;
  rawPatterns?: readonly TlsMatchPattern[];
  snippetPatterns?: readonly TlsSnippetPattern<TState>[];
  state: TState;
  text: string;
}

export function collectTlsVerificationDisabledFacts<TState>(
  options: TlsVerificationDisabledOptions<TState>,
): ObservedFact[] {
  const snippetFacts = (options.snippetPatterns ?? []).flatMap((entry) =>
    collectSnippetFacts({
      text: options.text,
      detector: options.detector,
      kind: 'security.tls-verification-disabled',
      pattern: entry.pattern,
      state: options.state,
      appliesTo: 'block',
      predicate: entry.predicate,
    }),
  );
  const rawFacts = (options.rawPatterns ?? []).flatMap((entry) =>
    collectMatchedFacts({
      text: options.text,
      detector: options.detector,
      kind: 'security.tls-verification-disabled',
      pattern: entry.pattern,
      appliesTo: 'block',
    }),
  );

  return [...snippetFacts, ...rawFacts];
}
