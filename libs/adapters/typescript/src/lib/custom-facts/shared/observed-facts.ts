import type { ObservedFact } from '@critiq/core-rules-engine';

import { toObservedRange } from '../../ast';
import type { CreateObservedFactOptions } from './context';

export function createObservedFact(
  options: CreateObservedFactOptions,
): ObservedFact {
  const range = toObservedRange(options.node);
  const primaryNodeId = options.nodeIds.get(options.node as object);
  const id = [
    'ts-detector',
    options.kind,
    range.startLine,
    range.startColumn,
    range.endLine,
    range.endColumn,
    primaryNodeId ?? 'node',
  ].join(':');

  return {
    id,
    kind: options.kind,
    appliesTo: options.appliesTo,
    primaryNodeId,
    range,
    text: options.text,
    props: options.props ?? {},
  };
}
