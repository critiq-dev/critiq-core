import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectSnippetFacts } from './collect-snippet-facts';

export interface JavaSensitiveDataEgressOptions<TState> {
  detector: string;
  matchesTainted: (text: string, state: TState) => boolean;
  state: TState;
  text: string;
}

const restTemplateEgressPattern =
  /\.(?:postForObject|postForEntity|exchange|patchForObject|getForObject)\s*\(/g;

const httpRequestBuilderPattern = /\bHttpRequest\.newBuilder\s*\(/g;

export function collectJavaSensitiveDataEgressFacts<TState>(
  options: JavaSensitiveDataEgressOptions<TState>,
): ObservedFact[] {
  const restFacts = collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.sensitive-data-egress',
    pattern: restTemplateEgressPattern,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet, state) =>
      options.matchesTainted(snippet.text, state),
    props: () => ({ sink: 'rest-template' }),
  });

  const httpFacts = collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.sensitive-data-egress',
    pattern: httpRequestBuilderPattern,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet, state) =>
      options.matchesTainted(snippet.text, state),
    props: () => ({ sink: 'http-request' }),
  });

  return [...restFacts, ...httpFacts];
}
