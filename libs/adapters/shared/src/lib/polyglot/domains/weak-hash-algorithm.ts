import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './shared';

export interface WeakHashAlgorithmOptions {
  detector: string;
  pattern: RegExp;
  text: string;
}

export function collectWeakHashFacts(
  options: WeakHashAlgorithmOptions,
): ObservedFact[] {
  return collectMatchedFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.weak-hash-algorithm',
    pattern: options.pattern,
    appliesTo: 'block',
  });
}
