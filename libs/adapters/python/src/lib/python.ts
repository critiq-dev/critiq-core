import {
  buildAnalyzedFileWithFacts,
  CREDENTIAL_IDENTIFIER_PATTERN,
  containsIdentifier,
  createObservedFactFromOffsets,
  findCallSnippets,
  findAllMatches,
  REDACTION_WRAPPER_PATTERN,
  SENSITIVE_LABEL_PATTERN,
  type CallSnippet,
} from '@critiq/adapter-shared';
import { createDiagnostic, type Diagnostic } from '@critiq/core-diagnostics';
import type { AnalyzedFile, ObservedFact } from '@critiq/core-rules-engine';

export interface PythonAnalysisSuccess {
  success: true;
  data: AnalyzedFile;
}

export interface PythonAnalysisFailure {
  success: false;
  diagnostics: Diagnostic[];
}

export type PythonAnalysisResult = PythonAnalysisSuccess | PythonAnalysisFailure;

export const pythonSourceAdapter = {
  packageName: '@critiq/adapter-python',
  supportedExtensions: ['.py'],
  supportedLanguages: ['python'],
  analyze: analyzePythonFile,
} as const;

const requestSourcePattern =
  /\b(?:request\.(?:args|cookies|data|files|form|headers)|request\.get_json\s*\(|request\.view_args|flask\.request\.)/;
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

interface PythonScanState {
  routeParameters: Set<string>;
  sqlInterpolatedIdentifiers: Set<string>;
  taintedIdentifiers: Set<string>;
}

function analyzePythonFile(path: string, text: string): PythonAnalysisResult {
  const syntaxDiagnostic = validatePythonSource(path, text);

  if (syntaxDiagnostic) {
    return {
      success: false,
      diagnostics: [syntaxDiagnostic],
    };
  }

  const state = collectPythonScanState(text);
  const facts = dedupeFacts([
    ...collectHardcodedCredentialFacts(text),
    ...collectSensitiveLoggingFacts(text, state),
    ...collectRequestPathFileReadFacts(text, state),
    ...collectCommandExecutionFacts(text, state),
    ...collectSqlInterpolationFacts(text, state),
    ...collectUnsafeDeserializationFacts(text, state),
    ...collectTlsVerificationDisabledFacts(text),
    ...collectInsecureHttpTransportFacts(text),
    ...collectWeakHashFacts(text),
  ]);

  return {
    success: true,
    data: buildAnalyzedFileWithFacts(path, 'python', text, facts),
  };
}

function validatePythonSource(path: string, text: string): Diagnostic | undefined {
  const unmatched = findFirstUnmatchedDelimiter(text, ['(', ')'], ['[', ']'], ['{', '}']);

  if (unmatched) {
    return createDiagnostic({
      code: 'adapter.python.parse-failed',
      message: `Python source at \`${path}\` has an unmatched \`${unmatched}\` delimiter.`,
      details: {
        path,
      },
    });
  }

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();

    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }

    if (line.startsWith('def ') && !/def\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)\s*:$/u.test(line)) {
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
  const taintedIdentifiers = new Set<string>(routeParameters);
  const sqlInterpolatedIdentifiers = new Set<string>();

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();

    if (line.length === 0) {
      continue;
    }

    const assignmentMatch = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/u.exec(line);

    if (!assignmentMatch) {
      continue;
    }

    const [, identifier, expression] = assignmentMatch;

    if (
      looksLikeRequestSource(expression) ||
      containsIdentifier(expression, taintedIdentifiers)
    ) {
      taintedIdentifiers.add(identifier);
    }

    if (
      looksLikeSqlInterpolation(expression) ||
      containsIdentifier(expression, sqlInterpolatedIdentifiers)
    ) {
      sqlInterpolatedIdentifiers.add(identifier);
    }
  }

  return {
    routeParameters,
    sqlInterpolatedIdentifiers,
    taintedIdentifiers,
  };
}

function collectRouteParameters(text: string): Set<string> {
  const parameters = new Set<string>();
  const lines = text.split(/\r?\n/);
  let pendingRoute = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (/^@app\.(?:get|post|put|patch|delete|route)\(/.test(line)) {
      pendingRoute = true;

      for (const match of line.matchAll(/<(?:(?:[^:>]+):)?([A-Za-z_][A-Za-z0-9_]*)>/g)) {
        parameters.add(match[1]);
      }

      continue;
    }

    if (pendingRoute && /^def\s+/.test(line)) {
      const definitionMatch = /^def\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)\s*:$/u.exec(
        line,
      );

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

function collectHardcodedCredentialFacts(text: string): ObservedFact[] {
  return findAllMatches(
    text,
    /(?:^|\n)\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["'][^"'\n]{8,}["']/g,
  )
    .filter(({ matchedText }) => CREDENTIAL_IDENTIFIER_PATTERN.test(matchedText))
    .map(({ matchedText, startOffset, endOffset }) =>
      createObservedFactFromOffsets(text, {
        detector: 'python-detector',
        appliesTo: 'file',
        kind: 'security.hardcoded-credentials',
        startOffset,
        endOffset,
        text: matchedText.trim(),
        props: {},
      }),
    );
}

function collectSensitiveLoggingFacts(
  text: string,
  state: PythonScanState,
): ObservedFact[] {
  return findCallSnippets(text, logCallPattern)
    .filter((snippet) => !REDACTION_WRAPPER_PATTERN.test(snippet.text))
    .filter(
      (snippet) =>
        SENSITIVE_LABEL_PATTERN.test(snippet.text) ||
        containsIdentifier(snippet.text, state.taintedIdentifiers),
    )
    .map((snippet) =>
      createDetectorFact(
        text,
        'function',
        'security.sensitive-data-in-logs-and-telemetry',
        snippet,
      ),
    );
}

function collectRequestPathFileReadFacts(
  text: string,
  state: PythonScanState,
): ObservedFact[] {
  return findCallSnippets(text, fileReadCallPattern)
    .filter(
      (snippet) =>
        looksLikeRequestSource(snippet.text) ||
        containsIdentifier(snippet.text, state.taintedIdentifiers),
    )
    .map((snippet) =>
      createDetectorFact(text, 'block', 'security.request-path-file-read', snippet),
    );
}

function collectCommandExecutionFacts(
  text: string,
  state: PythonScanState,
): ObservedFact[] {
  return findCallSnippets(text, commandCallPattern)
    .filter(
      (snippet) =>
        looksLikeRequestSource(snippet.text) ||
        containsIdentifier(snippet.text, state.taintedIdentifiers),
    )
    .map((snippet) =>
      createDetectorFact(
        text,
        'block',
        'security.command-execution-with-request-input',
        snippet,
      ),
    );
}

function collectSqlInterpolationFacts(
  text: string,
  state: PythonScanState,
): ObservedFact[] {
  return findCallSnippets(text, sqlCallPattern)
    .filter(
      (snippet) =>
        looksLikeSqlInterpolation(snippet.text) ||
        containsIdentifier(snippet.text, state.sqlInterpolatedIdentifiers),
    )
    .map((snippet) =>
      createDetectorFact(text, 'block', 'security.sql-interpolation', snippet),
    );
}

function collectUnsafeDeserializationFacts(
  text: string,
  state: PythonScanState,
): ObservedFact[] {
  return findCallSnippets(text, deserializeCallPattern)
    .filter(
      (snippet) =>
        looksLikeRequestSource(snippet.text) ||
        containsIdentifier(snippet.text, state.taintedIdentifiers),
    )
    .map((snippet) =>
      createDetectorFact(text, 'block', 'security.unsafe-deserialization', snippet),
    );
}

function collectTlsVerificationDisabledFacts(text: string): ObservedFact[] {
  const requestFacts = findCallSnippets(text, tlsVerificationCallPattern)
    .filter((snippet) => /\bverify\s*=\s*False\b/u.test(snippet.text))
    .map((snippet) =>
      createDetectorFact(
        text,
        'block',
        'security.tls-verification-disabled',
        snippet,
      ),
    );

  const contextFacts = findAllMatches(text, unverifiedContextPattern).map(
    ({ matchedText, startOffset, endOffset }) =>
      createObservedFactFromOffsets(text, {
        detector: 'python-detector',
        appliesTo: 'block',
        kind: 'security.tls-verification-disabled',
        startOffset,
        endOffset,
        text: matchedText,
        props: {},
      }),
  );

  return [...requestFacts, ...contextFacts];
}

function collectInsecureHttpTransportFacts(text: string): ObservedFact[] {
  return findCallSnippets(text, insecureHttpCallPattern)
    .filter((snippet) => hasRemotePlainHttpUrl(snippet.text))
    .map((snippet) =>
      createDetectorFact(text, 'block', 'security.insecure-http-transport', snippet),
    );
}

function collectWeakHashFacts(text: string): ObservedFact[] {
  return findAllMatches(text, weakHashCallPattern).map(
    ({ matchedText, startOffset, endOffset }) =>
      createObservedFactFromOffsets(text, {
        detector: 'python-detector',
        appliesTo: 'block',
        kind: 'security.weak-hash-algorithm',
        startOffset,
        endOffset,
        text: matchedText,
        props: {},
      }),
  );
}

function createDetectorFact(
  text: string,
  appliesTo: ObservedFact['appliesTo'],
  kind: string,
  snippet: CallSnippet,
): ObservedFact {
  return createObservedFactFromOffsets(text, {
    detector: 'python-detector',
    appliesTo,
    kind,
    startOffset: snippet.startOffset,
    endOffset: snippet.endOffset,
    text: snippet.text,
    props: {
      callee: snippet.calleeText,
    },
  });
}

function looksLikeRequestSource(expression: string): boolean {
  return requestSourcePattern.test(expression);
}

function looksLikeSqlInterpolation(expression: string): boolean {
  return (
    /\bf["'][\s\S]*\{[\s\S]+\}[\s\S]*["']/u.test(expression) ||
    /\.format\s*\(/.test(expression) ||
    /\+\s*[A-Za-z_][A-Za-z0-9_]*/.test(expression) ||
    /["'][^"'\n]*%[a-z][^"'\n]*["']\s*%\s*[A-Za-z_(]/i.test(expression)
  );
}

function hasRemotePlainHttpUrl(expression: string): boolean {
  return extractUrls(expression).some(
    (url) =>
      url.startsWith('http://') &&
      !/^http:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::|\/|$)/iu.test(url),
  );
}

function extractUrls(expression: string): string[] {
  return expression.match(/https?:\/\/[^\s"'`)\]]+/giu) ?? [];
}

function findFirstUnmatchedDelimiter(
  text: string,
  ...pairs: Array<[string, string]>
): string | undefined {
  let quote: '"' | "'" | null = null;
  let tripleQuote: `'''` | `"""` | null = null;
  let escapeNext = false;
  const stack: string[] = [];
  const openToClose = new Map(pairs);
  const closeToOpen = new Map(pairs.map(([open, close]) => [close, open]));

  for (let index = 0; index < text.length; index += 1) {
    const threeCharacters = text.slice(index, index + 3);
    const character = text[index];

    if (tripleQuote) {
      if (threeCharacters === tripleQuote) {
        tripleQuote = null;
        index += 2;
      }
      continue;
    }

    if (quote) {
      if (escapeNext) {
        escapeNext = false;
        continue;
      }

      if (character === '\\') {
        escapeNext = true;
        continue;
      }

      if (character === quote) {
        quote = null;
      }

      continue;
    }

    if (character === '#') {
      while (index < text.length && text[index] !== '\n') {
        index += 1;
      }
      continue;
    }

    if (threeCharacters === `'''` || threeCharacters === `"""`) {
      tripleQuote = threeCharacters as `'''` | `"""`;
      index += 2;
      continue;
    }

    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }

    if (openToClose.has(character)) {
      stack.push(character);
      continue;
    }

    const expectedOpen = closeToOpen.get(character);

    if (!expectedOpen) {
      continue;
    }

    const actualOpen = stack.pop();

    if (actualOpen !== expectedOpen) {
      return character;
    }
  }

  return stack.at(-1);
}

function dedupeFacts(facts: readonly ObservedFact[]): ObservedFact[] {
  const seen = new Set<string>();

  return facts.filter((fact) => {
    if (seen.has(fact.id)) {
      return false;
    }

    seen.add(fact.id);
    return true;
  });
}
