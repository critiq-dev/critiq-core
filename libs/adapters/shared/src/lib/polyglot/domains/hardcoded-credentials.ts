import type { ObservedFact } from '@critiq/core-rules-engine';

import { CREDENTIAL_IDENTIFIER_PATTERN } from '../../runtime';
import { collectMatchedFacts } from './collect-matched-facts';

export interface HardcodedCredentialOptions {
  appliesTo?: ObservedFact['appliesTo'];
  assignmentPattern: RegExp;
  detector: string;
  text: string;
}

export function collectHardcodedCredentialFacts(
  options: HardcodedCredentialOptions,
): ObservedFact[] {
  return collectMatchedFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.hardcoded-credentials',
    pattern: options.assignmentPattern,
    appliesTo: options.appliesTo ?? 'file',
    predicate: ({ matchedText }) =>
      CREDENTIAL_IDENTIFIER_PATTERN.test(matchedText),
    textValue: ({ matchedText }) => matchedText.trim(),
  });
}
