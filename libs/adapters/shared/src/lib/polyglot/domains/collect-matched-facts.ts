import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches, type TextMatch } from '../../runtime';
import { createOffsetFact } from '../fact-utils';

export interface CollectMatchedFactsOptions {
  text: string;
  detector: string;
  kind: string;
  pattern: RegExp;
  appliesTo: ObservedFact['appliesTo'];
  predicate?: (match: TextMatch) => boolean;
  props?: (match: TextMatch) => Record<string, unknown> | undefined;
  textValue?: (match: TextMatch) => string;
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
