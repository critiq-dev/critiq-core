import type { ObservedFact } from '@critiq/core-rules-engine';

import { hasRemotePlainHttpUrl } from '../text';
import { collectSnippetFacts } from './collect-snippet-facts';

export interface InsecureHttpTransportOptions<TState> {
  detector: string;
  pattern: RegExp;
  state: TState;
  text: string;
}

export function collectInsecureHttpTransportFacts<TState>(
  options: InsecureHttpTransportOptions<TState>,
): ObservedFact[] {
  return collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.insecure-http-transport',
    pattern: options.pattern,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet) => hasRemotePlainHttpUrl(snippet.text),
  });
}
