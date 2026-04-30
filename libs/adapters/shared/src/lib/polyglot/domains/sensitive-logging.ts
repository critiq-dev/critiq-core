import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  REDACTION_WRAPPER_PATTERN,
  SENSITIVE_LABEL_PATTERN,
} from '../../runtime';
import { collectSnippetFacts } from './collect-snippet-facts';

export interface SensitiveLoggingOptions<TState> {
  detector: string;
  matchesTainted: (text: string, state: TState) => boolean;
  pattern: RegExp;
  state: TState;
  text: string;
}

export function collectSensitiveLoggingFacts<TState>(
  options: SensitiveLoggingOptions<TState>,
): ObservedFact[] {
  return collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.sensitive-data-in-logs-and-telemetry',
    pattern: options.pattern,
    state: options.state,
    appliesTo: 'function',
    predicate: (snippet, state) =>
      !REDACTION_WRAPPER_PATTERN.test(snippet.text) &&
      (SENSITIVE_LABEL_PATTERN.test(snippet.text) ||
        options.matchesTainted(snippet.text, state)),
  });
}
