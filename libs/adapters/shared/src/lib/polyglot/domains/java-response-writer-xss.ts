import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';

const reflectedWriterPattern =
  /\.getWriter\s*\(\)\s*\.\s*(?:print|println|write)\s*\([\s\S]{0,800}?request\.(?:getParameter|getQueryString|getHeader)\s*\([^)]*\)\s*\)/gu;

export interface JavaResponseWriterXssOptions {
  detector: string;
  text: string;
}

export function collectJavaResponseWriterXssFacts(
  options: JavaResponseWriterXssOptions,
): ObservedFact[] {
  return collectMatchedFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.java-reflected-output-from-request',
    pattern: reflectedWriterPattern,
    appliesTo: 'block',
    props: () => ({ sink: 'response-writer' }),
    textValue: ({ matchedText }) => matchedText.trim(),
  });
}
