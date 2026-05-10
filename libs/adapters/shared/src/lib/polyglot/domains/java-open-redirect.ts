import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectSnippetFacts } from './collect-snippet-facts';

export interface JavaOpenRedirectOptions<TState> {
  detector: string;
  matchesTainted: (text: string, state: TState) => boolean;
  state: TState;
  text: string;
}

const javaRedirectSinkPattern =
  /\bsendRedirect\s*\(|\bnew\s+RedirectView\s*\(/g;

export function collectJavaOpenRedirectFacts<TState>(
  options: JavaOpenRedirectOptions<TState>,
): ObservedFact[] {
  return collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.open-redirect',
    pattern: javaRedirectSinkPattern,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet, state) =>
      options.matchesTainted(snippet.text, state),
  });
}
