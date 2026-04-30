import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectSnippetFacts } from './collect-snippet-facts';

export interface RequestPathFileReadOptions<TState> {
  detector: string;
  matchesTainted: (text: string, state: TState) => boolean;
  pattern: RegExp;
  state: TState;
  text: string;
}

export function collectRequestPathFileReadFacts<TState>(
  options: RequestPathFileReadOptions<TState>,
): ObservedFact[] {
  return collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.request-path-file-read',
    pattern: options.pattern,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet, state) =>
      options.matchesTainted(snippet.text, state),
  });
}
