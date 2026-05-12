import {
  collectCommandExecutionFacts,
  collectHardcodedCredentialFacts,
  collectInsecureHttpTransportFacts,
  collectRequestPathFileReadFacts,
  collectRustFrameworkSecurityFacts,
  collectSensitiveLoggingFacts,
  collectSharedArchivePathTraversalFacts,
  collectSharedExternalFileUploadFacts,
  collectSharedPermissiveFilePermissionFacts,
  collectSharedSensitiveDataEgressFacts,
  collectSqlInterpolationFacts,
  collectTlsVerificationDisabledFacts,
  collectTrackedIdentifiers,
  collectUnsafeDeserializationFacts,
  collectWeakHashFacts,
  containsIdentifier,
  createRegexPolyglotAdapter,
  findFirstUnmatchedDelimiter,
  type PolyglotAdapterDefinition,
  type SourceAnalysisFailure,
  type SourceAnalysisResult,
  type SourceAnalysisSuccess,
  type TrackedIdentifierState,
} from '@critiq/adapter-shared';
import { createDiagnostic, type Diagnostic } from '@critiq/core-diagnostics';

export type RustAnalysisSuccess = SourceAnalysisSuccess;
export type RustAnalysisFailure = SourceAnalysisFailure;
export type RustAnalysisResult = SourceAnalysisResult;

type RustScanState = TrackedIdentifierState;

const requestSourcePattern =
  /\b(?:request|req)\.(?:query_string|path|uri|match_info)\s*\(|\b(?:request|req)\.headers\s*\(\)\.get\s*\(/;
const hardcodedCredentialPattern =
  /(?:^|\n)\s*(?:const\s+[A-Z_][A-Z0-9_]*\s*:\s*&str|let\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*["'][^"'\n]{8,}["']/g;
const fileReadCallPattern =
  /\b(?:std::fs::read|std::fs::read_to_string|std::fs::File::open)\s*\(/g;
const commandCallPattern =
  /\b(?:arg|args)\s*\(/g;
const deserializeCallPattern =
  /\b(?:serde_json::from_str|serde_yaml::from_str|bincode::deserialize)\s*\(/g;
const logCallPattern =
  /\b(?:println|eprintln|log::(?:error|info|warn)|tracing::(?:error|info|warn))!\s*\(/g;
const sqlCallPattern = /\b(?:query|execute)\s*\(/g;
const insecureHttpCallPattern = /\breqwest::get\s*\(/g;
const dangerousCertPattern = /\bdanger_accept_invalid_certs\s*\(/g;
const weakHashCallPattern = /\b(?:md5::compute|Md5::new|Sha1::new)\s*\(/g;

const rustAdapterDefinition: PolyglotAdapterDefinition<RustScanState> = {
  language: 'rust',
  detector: 'rust-detector',
  validate: validateRustSource,
  collectState: collectRustScanState,
  collectFacts: ({ text, path, state, detector }) => [
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
      matchesTainted: matchesRustTainted,
    }),
    ...collectRequestPathFileReadFacts({
      text,
      detector,
      pattern: fileReadCallPattern,
      state,
      matchesTainted: matchesRustTainted,
    }),
    ...collectCommandExecutionFacts({
      text,
      detector,
      pattern: commandCallPattern,
      state,
      matchesTainted: matchesRustTainted,
    }),
    ...collectSqlInterpolationFacts({
      text,
      detector,
      pattern: sqlCallPattern,
      state,
      matchesSqlInterpolation: matchesRustSqlInterpolation,
    }),
    ...collectUnsafeDeserializationFacts({
      text,
      detector,
      pattern: deserializeCallPattern,
      state,
      matchesTainted: matchesRustTainted,
    }),
    ...collectTlsVerificationDisabledFacts({
      text,
      detector,
      state,
      snippetPatterns: [
        {
          pattern: dangerousCertPattern,
          predicate: (snippet) => /\btrue\b/u.test(snippet.text),
        },
      ],
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
    ...collectRustFrameworkSecurityFacts({ text, path, detector }),
    ...collectSharedExternalFileUploadFacts({
      text,
      detector,
      state,
      matchesTainted: matchesRustTainted,
    }),
    ...collectSharedArchivePathTraversalFacts({
      text,
      detector,
      state,
      matchesTainted: matchesRustTainted,
    }),
    ...collectSharedPermissiveFilePermissionFacts({
      text,
      detector,
      state,
      matchesTainted: matchesRustTainted,
    }),
    ...collectSharedSensitiveDataEgressFacts({
      text,
      detector,
      state,
      matchesTainted: matchesRustTainted,
    }),
  ],
};

export const { analyze: analyzeRustFile, sourceAdapter: rustSourceAdapter } =
  createRegexPolyglotAdapter({
    packageName: '@critiq/adapter-rust',
    supportedExtensions: ['.rs'] as const,
    supportedLanguages: ['rust'] as const,
    definition: rustAdapterDefinition,
  });

function validateRustSource(path: string, text: string): Diagnostic | undefined {
  const unmatched = findFirstUnmatchedDelimiter(
    text,
    [
      ['(', ')'],
      ['[', ']'],
      ['{', '}'],
    ],
    {
      lineCommentPrefixes: ['//'],
      quoteChars: [`"`, `'`],
    },
  );

  if (unmatched) {
    return createDiagnostic({
      code: 'adapter.rust.parse-failed',
      message: `Rust source at \`${path}\` has an unmatched \`${unmatched}\` delimiter.`,
      details: {
        path,
      },
    });
  }

  return undefined;
}

function collectRustScanState(text: string): RustScanState {
  return collectTrackedIdentifiers({
    text,
    assignmentPattern:
      /^let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(.+);$/u,
    stripLineComment: stripRustLineComment,
    isTaintedExpression: (expression, identifiers) =>
      looksLikeRustRequestSource(expression) ||
      containsIdentifier(expression, identifiers),
    isSqlInterpolatedExpression: (expression, identifiers) =>
      looksLikeRustSqlInterpolation(expression) ||
      containsIdentifier(expression, identifiers),
  });
}

function stripRustLineComment(line: string): string {
  return line.replace(/\/\/.*$/u, '');
}

function matchesRustTainted(
  expression: string,
  state: RustScanState,
): boolean {
  return (
    looksLikeRustRequestSource(expression) ||
    containsIdentifier(expression, state.taintedIdentifiers)
  );
}

function matchesRustSqlInterpolation(
  expression: string,
  state: RustScanState,
): boolean {
  return (
    looksLikeRustSqlInterpolation(expression) ||
    containsIdentifier(expression, state.sqlInterpolatedIdentifiers)
  );
}

function looksLikeRustRequestSource(expression: string): boolean {
  return requestSourcePattern.test(expression);
}

function looksLikeRustSqlInterpolation(expression: string): boolean {
  return (
    /\bformat!\s*\(/.test(expression) ||
    /"[^"\n]*\b(?:SELECT|UPDATE|INSERT|DELETE)\b[^"\n]*"\s*\+/.test(expression)
  );
}
