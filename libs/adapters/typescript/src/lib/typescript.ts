import { createDiagnostic, type Diagnostic } from '@critiq/core-diagnostics';
import type { AnalyzedFile } from '@critiq/core-rules-engine';
import { parse } from '@typescript-eslint/typescript-estree';
import { extname } from 'node:path';

import { buildTypeScriptControlFlow } from './control-flow';
import { collectAdditionalTypeScriptFacts } from './custom-facts';
import { buildObservedNodes } from './observed-nodes';

export interface TypeScriptAnalysisSuccess {
  success: true;
  data: AnalyzedFile;
}

export interface TypeScriptAnalysisFailure {
  success: false;
  diagnostics: Diagnostic[];
}

export type TypeScriptAnalysisResult =
  | TypeScriptAnalysisSuccess
  | TypeScriptAnalysisFailure;

export const typescriptSourceAdapter = {
  packageName: '@critiq/adapter-typescript',
  supportedExtensions: ['.js', '.jsx', '.ts', '.tsx'],
  supportedLanguages: ['javascript', 'typescript'],
  analyze: analyzeTypeScriptFile,
} as const;

function extensionToLanguage(path: string): 'typescript' | 'javascript' {
  switch (extname(path).toLowerCase()) {
    case '.js':
    case '.jsx':
      return 'javascript';
    case '.ts':
    case '.tsx':
    default:
      return 'typescript';
  }
}

function supportsJsx(path: string): boolean {
  return ['.jsx', '.tsx'].includes(extname(path).toLowerCase());
}

function sanitizeShebangs(raw: string): string {
  const lines = raw.split('\n');
  return lines
    .map((line, index) => {
      const shebangColumn = line.indexOf('#!');
      if (shebangColumn === -1) {
        return line;
      }
      if (index === 0 && shebangColumn === 0) {
        return line;
      }
      return `${' '.repeat(shebangColumn)}// shebang-removed${line.slice(shebangColumn + 2)}`;
    })
    .join('\n');
}

export function analyzeTypeScriptFile(
  path: string,
  text: string,
): TypeScriptAnalysisResult {
  try {
    const sanitized = sanitizeShebangs(text);
    const program = parse(sanitized, {
      comment: true,
      errorOnUnknownASTType: false,
      jsx: supportsJsx(path),
      loc: true,
      range: true,
      tokens: false,
      sourceType: 'module',
    });
    const { nodeIds, nodes } = buildObservedNodes(program, text);
    const semantics = buildTypeScriptControlFlow(program, text, nodeIds);
    const additionalFacts = collectAdditionalTypeScriptFacts({
      nodeIds,
      path,
      program,
      sourceText: text,
    });

    const controlFlow = semantics.controlFlow ?? {
      functions: [],
      blocks: [],
      edges: [],
      facts: [],
    };
    controlFlow.facts.push(...additionalFacts);
    semantics.controlFlow = controlFlow;

    return {
      success: true,
      data: {
        path,
        language: extensionToLanguage(path),
        text,
        nodes,
        semantics,
      },
    };
  } catch (error) {
    return {
      success: false,
      diagnostics: [
        createDiagnostic({
          code: 'typescript.parse.invalid',
          message:
            error instanceof Error
              ? error.message
              : 'Unexpected TypeScript parser failure.',
          details: {
            path,
          },
        }),
      ],
    };
  }
}

export function typescriptAdapterPackageName(): string {
  return '@critiq/adapter-typescript';
}
