import type { ObservedFact } from '@critiq/core-rules-engine';

import { findCallSnippets, type CallSnippet } from '../../runtime';
import { createSnippetFact } from '../fact-utils';

export interface CollectSnippetFactsOptions<TState> {
  text: string;
  detector: string;
  kind: string;
  pattern: RegExp;
  state: TState;
  appliesTo: ObservedFact['appliesTo'];
  predicate?: (snippet: CallSnippet, state: TState) => boolean;
  props?: (
    snippet: CallSnippet,
    state: TState,
  ) => Record<string, unknown> | undefined;
}

export function collectSnippetFacts<TState>(
  options: CollectSnippetFactsOptions<TState>,
): ObservedFact[] {
  return findCallSnippets(options.text, options.pattern)
    .filter((snippet) => options.predicate?.(snippet, options.state) ?? true)
    .map((snippet) =>
      createSnippetFact(options.text, {
        detector: options.detector,
        appliesTo: options.appliesTo,
        kind: options.kind,
        snippet,
        props: options.props?.(snippet, options.state),
      }),
    );
}
