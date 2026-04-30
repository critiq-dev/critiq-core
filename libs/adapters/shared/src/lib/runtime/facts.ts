import type { ObservedFact } from '@critiq/core-rules-engine';

import { createRangeFromOffsets } from './ranges';

export interface CreateFactOptions {
  detector: string;
  appliesTo: ObservedFact['appliesTo'];
  kind: string;
  startOffset: number;
  endOffset: number;
  text: string;
  props?: Record<string, unknown>;
}

export function createObservedFactFromOffsets(
  text: string,
  options: CreateFactOptions,
): ObservedFact {
  const range = createRangeFromOffsets(
    text,
    options.startOffset,
    options.endOffset,
  );
  const id = [
    options.detector,
    options.kind,
    range.startLine,
    range.startColumn,
    range.endLine,
    range.endColumn,
  ].join(':');

  return {
    id,
    kind: options.kind,
    appliesTo: options.appliesTo,
    range,
    text: options.text,
    props: options.props ?? {},
  };
}
