import {
  collectCommandExecutionFacts,
  collectGoEchoSensitiveBindingFacts,
  collectGoEchoUnsafeUploadFacts,
  collectGoFiberSensitiveBindingFacts,
  collectGoFiberUnsafeUploadFacts,
  collectGoGinSensitiveBindingFacts,
  collectGoGinTrustAllProxiesFacts,
  collectGoGinWildcardCorsWithCredentialsFacts,
  collectGoNetHttpMissingTimeoutFacts,
  collectGoOpenRedirectFacts,
  collectGoSensitiveDataEgressFacts,
  collectGoSsrfFacts,
  collectGoTarPathTraversalFacts,
  collectGoTemplateUnescapedRequestFacts,
  collectHardcodedCredentialFacts,
  collectInsecureHttpTransportFacts,
  collectRequestPathFileReadFacts,
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
  looksLikeGoExtendedRequestSource,
  type PolyglotAdapterDefinition,
  type SourceAnalysisFailure,
  type SourceAnalysisResult,
  type SourceAnalysisSuccess,
  type TrackedIdentifierState,
} from '@critiq/adapter-shared';
import { createDiagnostic, type Diagnostic } from '@critiq/core-diagnostics';

export type GoAnalysisSuccess = SourceAnalysisSuccess;
export type GoAnalysisFailure = SourceAnalysisFailure;
export type GoAnalysisResult = SourceAnalysisResult;

type GoScanState = TrackedIdentifierState;

const hardcodedCredentialPattern =
  /(?:^|\n)\s*(?:const|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*["'`][^"'`\n]{8,}["'`]/g;
const fileReadCallPattern = /\b(?:os|ioutil)\.ReadFile\s*\(/g;
const commandCallPattern = /\bexec\.Command(?:Context)?\s*\(/g;
const deserializeCallPattern =
  /\b(?:json|yaml)\.Unmarshal\s*\(|\b(?:json|yaml)\.NewDecoder\s*\(|\bDecode\s*\(/g;
const logCallPattern =
  /\b(?:log\.(?:Fatal|Fatalf|Print|Printf|Println)|logger\.(?:Error|Info|Warn)|slog\.(?:Error|Info|Warn))\s*\(/g;
const sqlCallPattern =
  /\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:Exec|ExecContext|Query|QueryContext|Raw|RawContext)\s*\(/g;
const insecureHttpCallPattern =
  /\b(?:http\.(?:Get|Head|Post|PostForm|NewRequest|NewRequestWithContext)|[A-Za-z_][A-Za-z0-9_]*\.(?:Get|Head|Post|PostForm))\s*\(/g;
const weakHashCallPattern = /\b(?:md5|sha1)\.(?:New|Sum)\s*\(/g;
const tlsVerificationPattern =
  /(?:&)?tls\.Config\s*\{[^}]*InsecureSkipVerify\s*:\s*true[^}]*\}/g;

const goAdapterDefinition: PolyglotAdapterDefinition<GoScanState> = {
  language: 'go',
  detector: 'go-detector',
  validate: validateGoSource,
  collectState: collectGoScanState,
  collectFacts: ({ text, state, detector, path }) => [
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
      matchesTainted: matchesGoTainted,
    }),
    ...collectRequestPathFileReadFacts({
      text,
      detector,
      pattern: fileReadCallPattern,
      state,
      matchesTainted: matchesGoTainted,
    }),
    ...collectCommandExecutionFacts({
      text,
      detector,
      pattern: commandCallPattern,
      state,
      matchesTainted: matchesGoTainted,
    }),
    ...collectSqlInterpolationFacts({
      text,
      detector,
      pattern: sqlCallPattern,
      state,
      matchesSqlInterpolation: matchesGoSqlInterpolation,
      ignoreSnippet: (snippet) => isGoFunctionDeclaration(text, snippet.startOffset),
    }),
    ...collectUnsafeDeserializationFacts({
      text,
      detector,
      pattern: deserializeCallPattern,
      state,
      matchesTainted: matchesGoTainted,
    }),
    ...collectTlsVerificationDisabledFacts({
      text,
      detector,
      state,
      rawPatterns: [{ pattern: tlsVerificationPattern }],
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
    ...collectGoOpenRedirectFacts({
      text,
      path,
      detector,
      state,
      matchesTainted: matchesGoTainted,
    }),
    ...collectGoSsrfFacts({
      text,
      path,
      detector,
      state,
      matchesTainted: matchesGoTainted,
    }),
    ...collectGoSensitiveDataEgressFacts({
      text,
      path,
      detector,
      state,
      matchesTainted: matchesGoTainted,
    }),
    ...collectGoTarPathTraversalFacts({ text, path, detector }),
    ...collectGoNetHttpMissingTimeoutFacts({ text, path, detector }),
    ...collectGoGinWildcardCorsWithCredentialsFacts({ text, path, detector }),
    ...collectGoGinTrustAllProxiesFacts({ text, path, detector }),
    ...collectGoGinSensitiveBindingFacts({ text, path, detector }),
    ...collectGoEchoSensitiveBindingFacts({ text, path, detector }),
    ...collectGoEchoUnsafeUploadFacts({ text, path, detector }),
    ...collectGoFiberSensitiveBindingFacts({ text, path, detector }),
    ...collectGoFiberUnsafeUploadFacts({ text, path, detector }),
    ...collectGoTemplateUnescapedRequestFacts({
      text,
      path,
      detector,
      state,
      matchesTainted: matchesGoTainted,
    }),
    ...collectSharedExternalFileUploadFacts({
      text,
      detector,
      state,
      matchesTainted: matchesGoTainted,
    }),
    ...collectSharedArchivePathTraversalFacts({
      text,
      detector,
      state,
      matchesTainted: matchesGoTainted,
    }),
    ...collectSharedPermissiveFilePermissionFacts({
      text,
      detector,
      state,
      matchesTainted: matchesGoTainted,
    }),
    ...collectSharedSensitiveDataEgressFacts({
      text,
      detector,
      state,
      matchesTainted: matchesGoTainted,
    }),
  ],
};

export const { analyze: analyzeGoFile, sourceAdapter: goSourceAdapter } =
  createRegexPolyglotAdapter({
    packageName: '@critiq/adapter-go',
    supportedExtensions: ['.go'] as const,
    supportedLanguages: ['go'] as const,
    definition: goAdapterDefinition,
  });

function validateGoSource(path: string, text: string): Diagnostic | undefined {
  if (!/^\s*package\s+[A-Za-z_][A-Za-z0-9_]*\s*$/m.test(text)) {
    return createDiagnostic({
      code: 'adapter.go.parse-failed',
      message: `Go source at \`${path}\` is missing a package declaration.`,
      details: {
        path,
      },
    });
  }

  const unmatched = findFirstUnmatchedDelimiter(
    text,
    [
      ['(', ')'],
      ['[', ']'],
      ['{', '}'],
    ],
    {
      lineCommentPrefixes: ['//'],
      quoteChars: [`"`, `'`, '`'],
    },
  );

  if (unmatched) {
    return createDiagnostic({
      code: 'adapter.go.parse-failed',
      message: `Go source at \`${path}\` has an unmatched \`${unmatched}\` delimiter.`,
      details: {
        path,
      },
    });
  }

  return undefined;
}

function collectGoScanState(text: string): GoScanState {
  return collectTrackedIdentifiers({
    text,
    assignmentPattern:
      /^(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?::=|=)\s*(.+)$/u,
    stripLineComment: stripGoLineComment,
    isTaintedExpression: (expression, identifiers) =>
      looksLikeGoExtendedRequestSource(expression) ||
      containsIdentifier(expression, identifiers),
    isSqlInterpolatedExpression: (expression, identifiers) =>
      looksLikeGoSqlInterpolation(expression) ||
      containsIdentifier(expression, identifiers),
  });
}

function stripGoLineComment(line: string): string {
  return line.replace(/\/\/.*$/u, '');
}

function matchesGoTainted(
  expression: string,
  state: GoScanState,
): boolean {
  return (
    looksLikeGoExtendedRequestSource(expression) ||
    containsIdentifier(expression, state.taintedIdentifiers)
  );
}

function matchesGoSqlInterpolation(
  expression: string,
  state: GoScanState,
): boolean {
  return (
    looksLikeGoSqlInterpolation(expression) ||
    containsIdentifier(expression, state.sqlInterpolatedIdentifiers)
  );
}

function looksLikeGoSqlInterpolation(expression: string): boolean {
  return (
    /\bfmt\.Sprintf\s*\(/.test(expression) ||
    /"[^"\n]*SELECT[\s\S]*"\s*\+/.test(expression) ||
    /\+\s*"[^"\n]*"/.test(expression)
  );
}

function isGoFunctionDeclaration(text: string, startOffset: number): boolean {
  const lineStart = text.lastIndexOf('\n', startOffset - 1) + 1;
  const linePrefix = text.slice(lineStart, startOffset);

  return /\bfunc\b/.test(linePrefix);
}
