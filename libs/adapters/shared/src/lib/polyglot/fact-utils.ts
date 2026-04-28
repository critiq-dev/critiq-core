import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  createObservedFactFromOffsets,
  type CallSnippet,
} from '../runtime/helpers';

export interface CreateOffsetFactOptions {
  detector: string;
  appliesTo: ObservedFact['appliesTo'];
  kind: string;
  startOffset: number;
  endOffset: number;
  text: string;
  props?: Record<string, unknown>;
}

export function createOffsetFact(
  text: string,
  options: CreateOffsetFactOptions,
): ObservedFact {
  return createObservedFactFromOffsets(text, options);
}

export function createSnippetFact(
  text: string,
  options: {
    detector: string;
    appliesTo: ObservedFact['appliesTo'];
    kind: string;
    snippet: CallSnippet;
    props?: Record<string, unknown>;
  },
): ObservedFact {
  return createOffsetFact(text, {
    detector: options.detector,
    appliesTo: options.appliesTo,
    kind: options.kind,
    startOffset: options.snippet.startOffset,
    endOffset: options.snippet.endOffset,
    text: options.snippet.text,
    props: {
      callee: options.snippet.calleeText,
      ...(options.props ?? {}),
    },
  });
}

export function dedupeFacts(facts: readonly ObservedFact[]): ObservedFact[] {
  const seen = new Set<string>();

  return facts.filter((fact) => {
    if (seen.has(fact.id)) {
      return false;
    }

    seen.add(fact.id);
    return true;
  });
}
