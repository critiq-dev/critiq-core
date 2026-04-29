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
  createRegexPolyglotAdapter,
  escapeRegExp,
  findFirstUnmatchedDelimiter,
  type PolyglotAdapterDefinition,
  type SourceAnalysisFailure,
  type SourceAnalysisResult,
  type SourceAnalysisSuccess,
  type TrackedIdentifierState,
} from '@critiq/adapter-shared';
import { createDiagnostic, type Diagnostic } from '@critiq/core-diagnostics';

export type PhpAnalysisSuccess = SourceAnalysisSuccess;
export type PhpAnalysisFailure = SourceAnalysisFailure;
export type PhpAnalysisResult = SourceAnalysisResult;

type PhpScanState = TrackedIdentifierState;

const requestSourcePattern =
  /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\bfilter_input\s*\(/;
const hardcodedCredentialPattern =
  /(?:^|\n)\s*(?:const\s+[A-Za-z_][A-Za-z0-9_]*|\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*["'][^"'\n]{8,}["']/g;
const fileReadCallPattern =
  /\b(?:file_get_contents|fopen|readfile|scandir|unlink|include|require(?:_once)?)\s*\(/g;
const commandCallPattern =
  /\b(?:exec|shell_exec|system|passthru|proc_open|popen)\s*\(/g;
const deserializeCallPattern =
  /\b(?:unserialize|yaml_parse)\s*\(/g;
const logCallPattern =
  /\berror_log\s*\(|\b(?:logger|log)->(?:debug|error|info|warning)\s*\(/g;
const sqlCallPattern =
  /\b(?:mysqli_query|pg_query|query|exec|prepare)\s*\(/g;
const insecureHttpCallPattern =
  /\b(?:file_get_contents|curl_init)\s*\(/g;
const curlSetOptionPattern = /\bcurl_setopt\s*\(/g;
const weakHashCallPattern =
  /\b(?:md5|sha1)\s*\(|\bhash\s*\(\s*['"](?:md5|sha1)['"]\s*,/g;

const phpAdapterDefinition: PolyglotAdapterDefinition<PhpScanState> = {
  language: 'php',
  detector: 'php-detector',
  validate: validatePhpSource,
  collectState: collectPhpScanState,
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
      matchesTainted: matchesPhpTainted,
    }),
    ...collectRequestPathFileReadFacts({
      text,
      detector,
      pattern: fileReadCallPattern,
      state,
      matchesTainted: matchesPhpTainted,
    }),
    ...collectCommandExecutionFacts({
      text,
      detector,
      pattern: commandCallPattern,
      state,
      matchesTainted: matchesPhpTainted,
    }),
    ...collectSqlInterpolationFacts({
      text,
      detector,
      pattern: sqlCallPattern,
      state,
      matchesSqlInterpolation: matchesPhpSqlInterpolation,
    }),
    ...collectUnsafeDeserializationFacts({
      text,
      detector,
      pattern: deserializeCallPattern,
      state,
      matchesTainted: matchesPhpTainted,
    }),
    ...collectTlsVerificationDisabledFacts({
      text,
      detector,
      state,
      snippetPatterns: [
        {
          pattern: curlSetOptionPattern,
          predicate: (snippet) =>
            /CURLOPT_SSL_VERIFYPEER\s*,\s*false/iu.test(snippet.text) ||
            /CURLOPT_SSL_VERIFYHOST\s*,\s*0/iu.test(snippet.text),
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
  ],
};

export const { analyze: analyzePhpFile, sourceAdapter: phpSourceAdapter } =
  createRegexPolyglotAdapter({
    packageName: '@critiq/adapter-php',
    supportedExtensions: ['.php'] as const,
    supportedLanguages: ['php'] as const,
    definition: phpAdapterDefinition,
  });

function validatePhpSource(path: string, text: string): Diagnostic | undefined {
  const unmatched = findFirstUnmatchedDelimiter(
    text,
    [
      ['(', ')'],
      ['[', ']'],
      ['{', '}'],
    ],
    {
      lineCommentPrefixes: ['//', '#'],
      quoteChars: [`"`, `'`],
    },
  );

  if (unmatched) {
    return createDiagnostic({
      code: 'adapter.php.parse-failed',
      message: `PHP source at \`${path}\` has an unmatched \`${unmatched}\` delimiter.`,
      details: {
        path,
      },
    });
  }

  return undefined;
}

function collectPhpScanState(text: string): PhpScanState {
  return collectTrackedIdentifiers({
    text,
    assignmentPattern: /^\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+);$/u,
    stripLineComment: stripPhpLineComment,
    isTaintedExpression: (expression, identifiers) =>
      looksLikePhpRequestSource(expression) ||
      containsPhpIdentifier(expression, identifiers),
    isSqlInterpolatedExpression: (expression, identifiers) =>
      looksLikePhpSqlInterpolation(expression) ||
      containsPhpIdentifier(expression, identifiers),
  });
}

function stripPhpLineComment(line: string): string {
  return line.replace(/(?:\/\/|#).*$/u, '');
}

function containsPhpIdentifier(
  text: string,
  identifiers: ReadonlySet<string>,
): boolean {
  return [...identifiers].some((identifier) =>
    new RegExp(`\\$${escapeRegExp(identifier)}\\b`, 'u').test(text),
  );
}

function matchesPhpTainted(
  expression: string,
  state: PhpScanState,
): boolean {
  return (
    looksLikePhpRequestSource(expression) ||
    containsPhpIdentifier(expression, state.taintedIdentifiers)
  );
}

function matchesPhpSqlInterpolation(
  expression: string,
  state: PhpScanState,
): boolean {
  return (
    looksLikePhpSqlInterpolation(expression) ||
    containsPhpIdentifier(expression, state.sqlInterpolatedIdentifiers)
  );
}

function looksLikePhpRequestSource(expression: string): boolean {
  return requestSourcePattern.test(expression);
}

function looksLikePhpSqlInterpolation(expression: string): boolean {
  return (
    /\bsprintf\s*\(/.test(expression) ||
    /["'][^"'\n]*\b(?:SELECT|UPDATE|INSERT|DELETE)\b[^"'\n]*["']\s*\./i.test(
      expression,
    ) ||
    /\.\s*\$[A-Za-z_][A-Za-z0-9_]*/.test(expression)
  );
}
