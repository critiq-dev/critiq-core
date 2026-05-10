import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';

export interface SpringConfigDebugExposureOptions {
  detector: string;
  path: string;
  text: string;
}

export function collectSpringConfigDebugExposureFacts(
  options: SpringConfigDebugExposureOptions,
): ObservedFact[] {
  if (!/\.properties$/iu.test(options.path)) {
    return [];
  }

  const debugPairs = collectMatchedFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.spring-debug-exposure',
    pattern: /^\s*debug\s*=\s*true\b/gm,
    appliesTo: 'file',
    props: () => ({ reason: 'debug-true-property' }),
    textValue: ({ matchedText }) => matchedText.trim(),
  });

  const verboseLogging = collectMatchedFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.spring-debug-exposure',
    pattern: /^\s*logging\.level\.(?:root|\*)\s*=\s*DEBUG\b/gim,
    appliesTo: 'file',
    props: () => ({ reason: 'verbose-root-logging' }),
    textValue: ({ matchedText }) => matchedText.trim(),
  });

  const actuatorWildcard = collectMatchedFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.spring-debug-exposure',
    pattern:
      /^\s*management\.endpoints\.web\.exposure\.include\s*=\s*\*\s*$/gm,
    appliesTo: 'file',
    props: () => ({ reason: 'actuator-expose-all' }),
    textValue: ({ matchedText }) => matchedText.trim(),
  });

  return [...debugPairs, ...verboseLogging, ...actuatorWildcard];
}
