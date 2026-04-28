import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  findAllMatches,
  findCallSnippets,
  type CallSnippet,
} from '../../runtime/helpers';
import {
  createOffsetFact,
  createSnippetFact,
} from '../fact-utils';

interface PatternMatch {
  matchedText: string;
  startOffset: number;
  endOffset: number;
}

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
    .filter(
      (snippet) =>
        options.predicate?.(snippet, options.state) ?? true,
    )
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

export interface CollectMatchedFactsOptions {
  text: string;
  detector: string;
  kind: string;
  pattern: RegExp;
  appliesTo: ObservedFact['appliesTo'];
  predicate?: (match: PatternMatch) => boolean;
  props?: (match: PatternMatch) => Record<string, unknown> | undefined;
  textValue?: (match: PatternMatch) => string;
}

export function collectMatchedFacts(
  options: CollectMatchedFactsOptions,
): ObservedFact[] {
  return findAllMatches(options.text, options.pattern)
    .filter((match) => options.predicate?.(match) ?? true)
    .map((match) =>
      createOffsetFact(options.text, {
        detector: options.detector,
        appliesTo: options.appliesTo,
        kind: options.kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: options.textValue?.(match) ?? match.matchedText,
        props: options.props?.(match),
      }),
    );
}
