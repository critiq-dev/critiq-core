import {
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
  createRegexPolyglotAdapter,
  findFirstUnmatchedDelimiter,
  type PolyglotAdapterDefinition,
  type SourceAnalysisFailure,
  type SourceAnalysisResult,
  type SourceAnalysisSuccess,
  type TrackedIdentifierState,
} from '@critiq/adapter-shared';
import { createDiagnostic, type Diagnostic } from '@critiq/core-diagnostics';

export type JavaAnalysisSuccess = SourceAnalysisSuccess;
export type JavaAnalysisFailure = SourceAnalysisFailure;
export type JavaAnalysisResult = SourceAnalysisResult;

type JavaScanState = TrackedIdentifierState;

const requestSourcePattern =
  /\b(?:request|req)\.(?:getHeader|getParameter|getPathInfo|getQueryString|getRequestURI|getServletPath|getCookies)\s*\(/;
const hardcodedCredentialPattern =
  /(?:^|\n)\s*(?:private|protected|public|static|final|\s)*[A-Za-z_$][A-Za-z0-9_$<>\[\]]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["'][^"'`\n]{8,}["']/g;
const fileReadCallPattern =
  /\b(?:Files\.(?:readAllBytes|readAllLines|readString|newInputStream)|new\s+File(?:InputStream|Reader)?)\s*\(/g;
const commandCallPattern = /\b(?:exec|ProcessBuilder)\s*\(/g;
const deserializeCallPattern =
  /\b(?:new\s+ObjectInputStream|new\s+XMLDecoder|(?:mapper|objectMapper)\.(?:readTree|readValue)|SerializationUtils\.deserialize)\s*\(/g;
const logCallPattern =
  /\b(?:log|logger|LOGGER)\.(?:debug|error|info|trace|warn)\s*\(/g;
const sqlCallPattern =
  /\b(?:[A-Za-z_][A-Za-z0-9_\.]*\.)?(?:execute|executeQuery|executeUpdate|prepareStatement|query|update)\s*\(/g;
const insecureHttpCallPattern =
  /\b(?:HttpRequest\.newBuilder|new\s+URL)\s*\(/g;
const hostnameVerifierPattern =
  /\b(?:hostnameVerifier|setHostnameVerifier)\s*\(/g;
const noopHostnameVerifierPattern = /\bNoopHostnameVerifier\.INSTANCE\b/g;
const weakHashCallPattern =
  /\bMessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-1)"\s*\)/g;

const javaAdapterDefinition: PolyglotAdapterDefinition<JavaScanState> = {
  language: 'java',
  detector: 'java-detector',
  validate: validateJavaSource,
  collectState: collectJavaScanState,
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
      matchesTainted: matchesJavaTainted,
    }),
    ...collectRequestPathFileReadFacts({
      text,
      detector,
      pattern: fileReadCallPattern,
      state,
      matchesTainted: matchesJavaTainted,
    }),
    ...collectCommandExecutionFacts({
      text,
      detector,
      pattern: commandCallPattern,
      state,
      matchesTainted: matchesJavaTainted,
    }),
    ...collectSqlInterpolationFacts({
      text,
      detector,
      pattern: sqlCallPattern,
      state,
      matchesSqlInterpolation: matchesJavaSqlInterpolation,
    }),
    ...collectUnsafeDeserializationFacts({
      text,
      detector,
      pattern: deserializeCallPattern,
      state,
      matchesTainted: matchesJavaTainted,
    }),
    ...collectTlsVerificationDisabledFacts({
      text,
      detector,
      state,
      snippetPatterns: [
        {
          pattern: hostnameVerifierPattern,
          predicate: (snippet) => /\btrue\b/u.test(snippet.text),
        },
      ],
      rawPatterns: [{ pattern: noopHostnameVerifierPattern }],
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

export const { analyze: analyzeJavaFile, sourceAdapter: javaSourceAdapter } =
  createRegexPolyglotAdapter({
    packageName: '@critiq/adapter-java',
    supportedExtensions: ['.java'] as const,
    supportedLanguages: ['java'] as const,
    definition: javaAdapterDefinition,
  });

function validateJavaSource(path: string, text: string): Diagnostic | undefined {
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
      code: 'adapter.java.parse-failed',
      message: `Java source at \`${path}\` has an unmatched \`${unmatched}\` delimiter.`,
      details: {
        path,
      },
    });
  }

  return undefined;
}

function collectJavaScanState(text: string): JavaScanState {
  return collectTrackedIdentifiers({
    text,
    assignmentPattern:
      /^(?:private|protected|public|static|final|\s)*[A-Za-z_$][A-Za-z0-9_$<>\[\]]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+);$/u,
    stripLineComment: stripJavaLineComment,
    isTaintedExpression: (expression, identifiers) =>
      looksLikeJavaRequestSource(expression) ||
      containsIdentifier(expression, identifiers),
    isSqlInterpolatedExpression: (expression, identifiers) =>
      looksLikeJavaSqlInterpolation(expression) ||
      containsIdentifier(expression, identifiers),
  });
}

function stripJavaLineComment(line: string): string {
  return line.replace(/\/\/.*$/u, '');
}

function matchesJavaTainted(
  expression: string,
  state: JavaScanState,
): boolean {
  return (
    looksLikeJavaRequestSource(expression) ||
    containsIdentifier(expression, state.taintedIdentifiers)
  );
}

function matchesJavaSqlInterpolation(
  expression: string,
  state: JavaScanState,
): boolean {
  return (
    looksLikeJavaSqlInterpolation(expression) ||
    containsIdentifier(expression, state.sqlInterpolatedIdentifiers)
  );
}

function looksLikeJavaRequestSource(expression: string): boolean {
  return requestSourcePattern.test(expression);
}

function looksLikeJavaSqlInterpolation(expression: string): boolean {
  return (
    /\bString\.format\s*\(/.test(expression) ||
    /\.formatted\s*\(/.test(expression) ||
    /"[^"\n]*\b(?:SELECT|UPDATE|INSERT|DELETE)\b[^"\n]*"\s*\+/.test(expression) ||
    /\+\s*"/.test(expression)
  );
}
