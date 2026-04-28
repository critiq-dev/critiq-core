import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectSnippetFacts } from './shared';

export interface CommandExecutionOptions<TState> {
  detector: string;
  matchesTainted: (text: string, state: TState) => boolean;
  pattern: RegExp;
  state: TState;
  text: string;
}

export function collectCommandExecutionFacts<TState>(
  options: CommandExecutionOptions<TState>,
): ObservedFact[] {
  return collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.command-execution-with-request-input',
    pattern: options.pattern,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet, state) =>
      options.matchesTainted(snippet.text, state),
  });
}
