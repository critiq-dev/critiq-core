import {
  analyzePolyglotFile,
  collectCommandExecutionFacts,
  collectHardcodedCredentialFacts,
  collectInsecureHttpTransportFacts,
  collectRequestPathFileReadFacts,
  collectSensitiveLoggingFacts,
  collectSqlInterpolationFacts,
  collectTlsVerificationDisabledFacts,
  collectTrackedIdentifiers,
  collectUnsafeDeserializationFacts,
  collectWeakHashFacts,
  containsIdentifier,
  findFirstUnmatchedDelimiter,
  stripHashLineComment,
  type PolyglotAdapterDefinition,
  type SourceAnalysisFailure,
  type SourceAnalysisResult,
  type SourceAnalysisSuccess,
  type TrackedIdentifierState,
} from '@critiq/adapter-shared';
import { createDiagnostic, type Diagnostic } from '@critiq/core-diagnostics';

export type PythonAnalysisSuccess = SourceAnalysisSuccess;
export type PythonAnalysisFailure = SourceAnalysisFailure;
export type PythonAnalysisResult = SourceAnalysisResult;

export const pythonSourceAdapter = {
  packageName: '@critiq/adapter-python',
  supportedExtensions: ['.py'],
  supportedLanguages: ['python'],
  analyze: analyzePythonFile,
} as const;

interface PythonScanState extends TrackedIdentifierState {
  routeParameters: Set<string>;
}

const requestSourcePattern =
  /\b(?:request\.(?:args|cookies|data|files|form|headers)|request\.get_json\s*\(|request\.view_args|flask\.request\.)/;
const hardcodedCredentialPattern =
  /(?:^|\n)\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["'][^"'\n]{8,}["']/g;
const fileReadCallPattern =
  /\b(?:open|[A-Za-z_][A-Za-z0-9_\.]*\.read_(?:bytes|text))\s*\(/g;
const commandCallPattern =
  /\b(?:os\.popen|os\.system|subprocess\.(?:Popen|call|check_output|run))\s*\(/g;
const deserializeCallPattern =
  /\b(?:json\.loads|marshal\.loads|pickle\.load|pickle\.loads|yaml\.load)\s*\(/g;
const logCallPattern =
  /\b(?:app\.logger|logger|logging)\.(?:critical|debug|error|exception|info|warning)\s*\(/g;
const sqlCallPattern =
  /\b(?:[A-Za-z_][A-Za-z0-9_\.]*\.)?(?:execute|executemany)\s*\(/g;
const insecureHttpCallPattern =
  /\b(?:requests|httpx)\.(?:delete|get|head|options|patch|post|put|request)\s*\(|\burllib\.request\.urlopen\s*\(|\b[A-Za-z_][A-Za-z0-9_]*\.(?:delete|get|head|options|patch|post|put|request)\s*\(/g;
const tlsVerificationCallPattern =
  /\b(?:requests|httpx)\.(?:delete|get|head|options|patch|post|put|request)\s*\(|\b[A-Za-z_][A-Za-z0-9_]*\.(?:delete|get|head|options|patch|post|put|request)\s*\(/g;
const unverifiedContextPattern = /\bssl\._create_unverified_context\s*\(/g;
const weakHashCallPattern = /\bhashlib\.(?:md5|sha1)\s*\(/g;

const pythonAdapterDefinition: PolyglotAdapterDefinition<PythonScanState> = {
  language: 'python',
  detector: 'python-detector',
  validate: validatePythonSource,
  collectState: collectPythonScanState,
  collectFacts: ({ text, state, detector }) => [
    ...collectHardcodedCredentialFacts({
      text,
      detector,
      assignmentPattern: hardcodedCredentialPattern,
    }),
    ...collectSensitiveLoggingFacts({
      text,
      detector,
      pattern: logCallPattern,
      state,
      matchesTainted: matchesPythonTainted,
    }),
    ...collectRequestPathFileReadFacts({
      text,
      detector,
      pattern: fileReadCallPattern,
      state,
      matchesTainted: matchesPythonTainted,
    }),
    ...collectCommandExecutionFacts({
      text,
      detector,
      pattern: commandCallPattern,
      state,
      matchesTainted: matchesPythonTainted,
    }),
    ...collectSqlInterpolationFacts({
      text,
      detector,
      pattern: sqlCallPattern,
      state,
      matchesSqlInterpolation: matchesPythonSqlInterpolation,
    }),
    ...collectUnsafeDeserializationFacts({
      text,
      detector,
      pattern: deserializeCallPattern,
      state,
      matchesTainted: matchesPythonTainted,
    }),
    ...collectTlsVerificationDisabledFacts({
      text,
      detector,
      state,
      snippetPatterns: [
        {
          pattern: tlsVerificationCallPattern,
          predicate: (snippet) => /\bverify\s*=\s*False\b/u.test(snippet.text),
        },
      ],
      rawPatterns: [{ pattern: unverifiedContextPattern }],
    }),
    ...collectInsecureHttpTransportFacts({
      text,
      detector,
      pattern: insecureHttpCallPattern,
      state,
    }),
    ...collectWeakHashFacts({
      text,
      detector,
      pattern: weakHashCallPattern,
    }),
  ],
};

function analyzePythonFile(path: string, text: string): PythonAnalysisResult {
  return analyzePolyglotFile(pythonAdapterDefinition, path, text);
}

function validatePythonSource(path: string, text: string): Diagnostic | undefined {
  const unmatched = findFirstUnmatchedDelimiter(
    text,
    [
      ['(', ')'],
      ['[', ']'],
      ['{', '}'],
    ],
    {
      lineCommentPrefixes: ['#'],
      quoteChars: [`"`, `'`],
      tripleQuotes: [`'''`, `"""`],
    },
  );

  if (unmatched) {
    return createDiagnostic({
      code: 'adapter.python.parse-failed',
      message: `Python source at \`${path}\` has an unmatched \`${unmatched}\` delimiter.`,
      details: {
        path,
      },
    });
  }

  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim();

    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }

    if (
      line.startsWith('def ') &&
      !/def\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)\s*:$/u.test(line)
    ) {
      return createDiagnostic({
        code: 'adapter.python.parse-failed',
        message: `Python source at \`${path}\` contains a malformed function definition.`,
        details: {
          path,
        },
      });
    }
  }

  return undefined;
}

function collectPythonScanState(text: string): PythonScanState {
  const routeParameters = collectRouteParameters(text);
  const tracked = collectTrackedIdentifiers({
    text,
    assignmentPattern: /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/u,
    stripLineComment: stripPythonLineComment,
    seedTaintedIdentifiers: routeParameters,
    isTaintedExpression: (expression, identifiers) =>
      looksLikePythonRequestSource(expression) ||
      containsIdentifier(expression, identifiers),
    isSqlInterpolatedExpression: (expression, identifiers) =>
      looksLikePythonSqlInterpolation(expression) ||
      containsIdentifier(expression, identifiers),
  });

  return {
    ...tracked,
    routeParameters,
  };
}

function collectRouteParameters(text: string): Set<string> {
  const parameters = new Set<string>();
  const lines = text.split(/\r?\n/u);
  let pendingRoute = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (/^@app\.(?:get|post|put|patch|delete|route)\(/.test(line)) {
      pendingRoute = true;

      for (const match of line.matchAll(
        /<(?:(?:[^:>]+):)?([A-Za-z_][A-Za-z0-9_]*)>/g,
      )) {
        parameters.add(match[1]);
      }

      continue;
    }

    if (pendingRoute && /^def\s+/.test(line)) {
      const definitionMatch =
        /^def\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)\s*:$/u.exec(line);

      if (definitionMatch) {
        for (const rawParameter of definitionMatch[1].split(',')) {
          const identifier = rawParameter.split(':')[0]?.trim();

          if (identifier && identifier !== 'self') {
            parameters.add(identifier.replace(/=.*/, '').trim());
          }
        }
      }

      pendingRoute = false;
      continue;
    }

    if (!line.startsWith('@')) {
      pendingRoute = false;
    }
  }

  return parameters;
}

function stripPythonLineComment(line: string): string {
  return stripHashLineComment(line);
}

function matchesPythonTainted(
  expression: string,
  state: PythonScanState,
): boolean {
  return (
    looksLikePythonRequestSource(expression) ||
    containsIdentifier(expression, state.taintedIdentifiers)
  );
}

function matchesPythonSqlInterpolation(
  expression: string,
  state: PythonScanState,
): boolean {
  return (
    looksLikePythonSqlInterpolation(expression) ||
    containsIdentifier(expression, state.sqlInterpolatedIdentifiers)
  );
}

function looksLikePythonRequestSource(expression: string): boolean {
  return requestSourcePattern.test(expression);
}

function looksLikePythonSqlInterpolation(expression: string): boolean {
  return (
    /\bf["'][\s\S]*\{[\s\S]+\}[\s\S]*["']/u.test(expression) ||
    /\.format\s*\(/.test(expression) ||
    /\+\s*[A-Za-z_][A-Za-z0-9_]*/.test(expression) ||
    /["'][^"'\n]*%[a-z][^"'\n]*["']\s*%\s*[A-Za-z_(]/i.test(expression)
  );
}
