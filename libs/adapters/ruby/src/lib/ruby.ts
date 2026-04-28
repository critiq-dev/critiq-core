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

export type RubyAnalysisSuccess = SourceAnalysisSuccess;
export type RubyAnalysisFailure = SourceAnalysisFailure;
export type RubyAnalysisResult = SourceAnalysisResult;

export const rubySourceAdapter = {
  packageName: '@critiq/adapter-ruby',
  supportedExtensions: ['.rb'],
  supportedLanguages: ['ruby'],
  analyze: analyzeRubyFile,
} as const;

type RubyScanState = TrackedIdentifierState;

const requestSourcePattern =
  /\b(?:params\[[^\]]+\]|request\.(?:params|headers|query_parameters)|cookies\[[^\]]+\])/;
const hardcodedCredentialPattern =
  /(?:^|\n)\s*(?:[A-Z_][A-Z0-9_]*|[a-z_][A-Za-z0-9_]*)\s*=\s*["'][^"'\n]{8,}["']/g;
const fileReadCallPattern =
  /\b(?:File\.(?:binread|foreach|open|read)|IO\.(?:binread|read|readlines)|Pathname\.new)\s*\(/g;
const commandCallPattern =
  /\b(?:system|exec|spawn|IO\.popen|Open3\.(?:capture2|capture2e|capture3|popen2|popen3))\s*\(/g;
const deserializeCallPattern =
  /\b(?:Marshal\.load|YAML\.load|Psych\.load)\s*\(/g;
const logCallPattern =
  /\b(?:logger|Rails\.logger)\.(?:debug|error|fatal|info|warn)\s*\(/g;
const sqlCallPattern =
  /\b(?:find_by_sql|execute|exec_query|where)\s*\(/g;
const insecureHttpCallPattern =
  /\b(?:URI\.open|OpenURI\.open_uri|Net::HTTP\.get(?:_response)?|Faraday\.(?:delete|get|patch|post|put))\s*\(/g;
const tlsVerifyNonePattern = /\bOpenSSL::SSL::VERIFY_NONE\b/g;
const weakHashCallPattern =
  /\bDigest::(?:MD5|SHA1)\.(?:base64digest|digest|hexdigest|new)\s*\(/g;

const rubyAdapterDefinition: PolyglotAdapterDefinition<RubyScanState> = {
  language: 'ruby',
  detector: 'ruby-detector',
  validate: validateRubySource,
  collectState: collectRubyScanState,
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
      matchesTainted: matchesRubyTainted,
    }),
    ...collectRequestPathFileReadFacts({
      text,
      detector,
      pattern: fileReadCallPattern,
      state,
      matchesTainted: matchesRubyTainted,
    }),
    ...collectCommandExecutionFacts({
      text,
      detector,
      pattern: commandCallPattern,
      state,
      matchesTainted: matchesRubyTainted,
    }),
    ...collectSqlInterpolationFacts({
      text,
      detector,
      pattern: sqlCallPattern,
      state,
      matchesSqlInterpolation: matchesRubySqlInterpolation,
    }),
    ...collectUnsafeDeserializationFacts({
      text,
      detector,
      pattern: deserializeCallPattern,
      state,
      matchesTainted: matchesRubyTainted,
    }),
    ...collectTlsVerificationDisabledFacts({
      text,
      detector,
      state,
      rawPatterns: [{ pattern: tlsVerifyNonePattern }],
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

function analyzeRubyFile(path: string, text: string): RubyAnalysisResult {
  return analyzePolyglotFile(rubyAdapterDefinition, path, text);
}

function validateRubySource(path: string, text: string): Diagnostic | undefined {
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
    },
  );

  if (unmatched) {
    return createDiagnostic({
      code: 'adapter.ruby.parse-failed',
      message: `Ruby source at \`${path}\` has an unmatched \`${unmatched}\` delimiter.`,
      details: {
        path,
      },
    });
  }

  return undefined;
}

function collectRubyScanState(text: string): RubyScanState {
  return collectTrackedIdentifiers({
    text,
    assignmentPattern:
      /^([A-Z_][A-Z0-9_]*|[a-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/u,
    stripLineComment: stripRubyLineComment,
    isTaintedExpression: (expression, identifiers) =>
      looksLikeRubyRequestSource(expression) ||
      containsIdentifier(expression, identifiers),
    isSqlInterpolatedExpression: (expression, identifiers) =>
      looksLikeRubySqlInterpolation(expression) ||
      containsIdentifier(expression, identifiers),
  });
}

function stripRubyLineComment(line: string): string {
  return stripHashLineComment(line);
}

function matchesRubyTainted(
  expression: string,
  state: RubyScanState,
): boolean {
  return (
    looksLikeRubyRequestSource(expression) ||
    containsIdentifier(expression, state.taintedIdentifiers)
  );
}

function matchesRubySqlInterpolation(
  expression: string,
  state: RubyScanState,
): boolean {
  return (
    looksLikeRubySqlInterpolation(expression) ||
    containsIdentifier(expression, state.sqlInterpolatedIdentifiers)
  );
}

function looksLikeRubyRequestSource(expression: string): boolean {
  return requestSourcePattern.test(expression);
}

function looksLikeRubySqlInterpolation(expression: string): boolean {
  return (
    /#\{[\s\S]+\}/u.test(expression) ||
    /\bformat\s*\(/.test(expression) ||
    /["'][^"'\n]*\b(?:SELECT|UPDATE|INSERT|DELETE)\b[^"'\n]*["']\s*\+/.test(
      expression,
    )
  );
}
