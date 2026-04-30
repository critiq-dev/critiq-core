import { buildAnalyzedFileWithFacts } from '../runtime';

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

export function createRegexPolyglotAdapter<
  TState,
  TPackageName extends string,
  TExtensions extends readonly string[],
  TLanguages extends readonly string[],
>(options: {
  packageName: TPackageName;
  supportedExtensions: TExtensions;
  supportedLanguages: TLanguages;
  definition: PolyglotAdapterDefinition<TState>;
}) {
  const analyze = (path: string, text: string): SourceAnalysisResult =>
    analyzePolyglotFile(options.definition, path, text);

  return {
    analyze,
    sourceAdapter: {
      packageName: options.packageName,
      supportedExtensions: options.supportedExtensions,
      supportedLanguages: options.supportedLanguages,
      analyze,
    },
  } as const;
}
