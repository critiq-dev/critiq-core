import { createDiagnostic, type Diagnostic } from '@critiq/core-diagnostics';
import type { AnalyzedFile } from '@critiq/core-rules-engine';

import { collectSqlFacts } from './facts';
import { buildObservedNodes } from './observed-nodes';
import { parseSql } from './parse';

export interface SqlAnalysisSuccess {
  success: true;
  data: AnalyzedFile;
}

export interface SqlAnalysisFailure {
  success: false;
  diagnostics: Diagnostic[];
}

export type SqlAnalysisResult = SqlAnalysisSuccess | SqlAnalysisFailure;

export const sqlSourceAdapter = {
  packageName: '@critiq/adapter-sql',
  supportedExtensions: ['.sql'] as const,
  supportedLanguages: ['sql'] as const,
  analyze: analyzeSqlFile,
} as const;

export function analyzeSqlFile(
  path: string,
  text: string,
): SqlAnalysisResult {
  const parseResult = parseSql(text);
  const diagnostics: Diagnostic[] = [];

  if (parseResult.success === false) {
    diagnostics.push(
      createDiagnostic({
        code: 'sql.parse.invalid',
        message: parseResult.error,
        details: { path },
      }),
    );
  }

  const facts = collectSqlFacts([], text);
  const { nodes } = buildObservedNodes(parseResult.success ? parseResult.ast : [], text);

  return {
    success: true,
    data: {
      path,
      language: 'sql',
      text,
      nodes,
      semantics: {
        controlFlow: {
          functions: [],
          blocks: [],
          edges: [],
          facts,
        },
      },
    },
  };
}

export function sqlAdapterPackageName(): string {
  return '@critiq/adapter-sql';
}
