import { buildAnalyzedFileWithFacts } from '../runtime/helpers';

import { dedupeFacts } from './fact-utils';
import type {
  PolyglotAdapterDefinition,
  SourceAnalysisResult,
} from './types';

export function analyzePolyglotFile<TState>(
  definition: PolyglotAdapterDefinition<TState>,
  path: string,
  text: string,
): SourceAnalysisResult {
  const syntaxDiagnostic = definition.validate?.(path, text);

  if (syntaxDiagnostic) {
    return {
      success: false,
      diagnostics: [syntaxDiagnostic],
    };
  }

  const state = definition.collectState(text);
  const facts = dedupeFacts(
    definition.collectFacts({
      detector: definition.detector,
      state,
      text,
    }),
  );

  return {
    success: true,
    data: buildAnalyzedFileWithFacts(path, definition.language, text, facts),
  };
}
