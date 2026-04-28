import type { ObservedFact } from '@critiq/core-rules-engine';

import { type CallSnippet } from '../../runtime/helpers';
import { collectSnippetFacts } from './shared';

export interface SqlInterpolationOptions<TState> {
  detector: string;
  ignoreSnippet?: (snippet: CallSnippet) => boolean;
  matchesSqlInterpolation: (text: string, state: TState) => boolean;
  pattern: RegExp;
  state: TState;
  text: string;
}

export function collectSqlInterpolationFacts<TState>(
  options: SqlInterpolationOptions<TState>,
): ObservedFact[] {
  return collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.sql-interpolation',
    pattern: options.pattern,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet, state) =>
      !(options.ignoreSnippet?.(snippet) ?? false) &&
      options.matchesSqlInterpolation(snippet.text, state),
  });
}
