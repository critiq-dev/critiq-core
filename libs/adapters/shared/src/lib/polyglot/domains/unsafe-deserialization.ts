import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectSnippetFacts } from './collect-snippet-facts';

export interface UnsafeDeserializationOptions<TState> {
  detector: string;
  matchesTainted: (text: string, state: TState) => boolean;
  pattern: RegExp;
  state: TState;
  text: string;
}

export function collectUnsafeDeserializationFacts<TState>(
  options: UnsafeDeserializationOptions<TState>,
): ObservedFact[] {
  return collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.unsafe-deserialization',
    pattern: options.pattern,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet, state) =>
      options.matchesTainted(snippet.text, state),
  });
}
