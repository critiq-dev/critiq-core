import {
  buildAnalyzedFileWithFacts,
  CREDENTIAL_IDENTIFIER_PATTERN,
  containsIdentifier,
  createObservedFactFromOffsets,
  findCallSnippets,
  findMatchingDelimiter,
  findAllMatches,
  REDACTION_WRAPPER_PATTERN,
  SENSITIVE_LABEL_PATTERN,
  type CallSnippet,
} from '@critiq/adapter-shared';
import { createDiagnostic, type Diagnostic } from '@critiq/core-diagnostics';
import type { AnalyzedFile, ObservedFact } from '@critiq/core-rules-engine';

export interface GoAnalysisSuccess {
  success: true;
  data: AnalyzedFile;
}

export interface GoAnalysisFailure {
  success: false;
  diagnostics: Diagnostic[];
}

export type GoAnalysisResult = GoAnalysisSuccess | GoAnalysisFailure;

export const goSourceAdapter = {
  packageName: '@critiq/adapter-go',
  supportedExtensions: ['.go'],
  supportedLanguages: ['go'],
  analyze: analyzeGoFile,
} as const;

const requestSourcePattern =
  /\br\.(?:Body|FormValue|PostFormValue|URL\.(?:Path|RawPath|RawQuery|Query\(\)\.Get)|Header\.Get|Cookie)\b/;
const fileReadCallPattern = /\b(?:os|ioutil)\.ReadFile\s*\(/g;
const commandCallPattern = /\bexec\.Command(?:Context)?\s*\(/g;
const deserializeCallPattern =
  /\b(?:json|yaml)\.Unmarshal\s*\(|\b(?:json|yaml)\.NewDecoder\s*\(|\bDecode\s*\(/g;
const logCallPattern =
  /\b(?:log\.(?:Fatal|Fatalf|Print|Printf|Println)|logger\.(?:Error|Info|Warn)|slog\.(?:Error|Info|Warn))\s*\(/g;
const sqlCallPattern =
  /\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:Exec|ExecContext|Query|QueryContext)\s*\(/g;
const insecureHttpCallPattern =
  /\b(?:http\.(?:Get|Head|Post|PostForm|NewRequest|NewRequestWithContext)|[A-Za-z_][A-Za-z0-9_]*\.(?:Get|Head|Post|PostForm))\s*\(/g;
const weakHashCallPattern = /\b(?:md5|sha1)\.(?:New|Sum)\s*\(/g;
const tlsVerificationPattern =
  /(?:&)?tls\.Config\s*\{[^}]*InsecureSkipVerify\s*:\s*true[^}]*\}/g;

interface GoScanState {
  sqlInterpolatedIdentifiers: Set<string>;
  taintedIdentifiers: Set<string>;
}

function analyzeGoFile(path: string, text: string): GoAnalysisResult {
  const syntaxDiagnostic = validateGoSource(path, text);

  if (syntaxDiagnostic) {
    return {
      success: false,
      diagnostics: [syntaxDiagnostic],
    };
  }

  const state = collectGoScanState(text);
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
    data: buildAnalyzedFileWithFacts(path, 'go', text, facts),
  };
}

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

  const unmatched = findFirstUnmatchedDelimiter(text, ['(', ')'], ['[', ']'], ['{', '}']);

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
  const taintedIdentifiers = new Set<string>();
  const sqlInterpolatedIdentifiers = new Set<string>();

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\/\/.*$/, '').trim();

    if (line.length === 0) {
      continue;
    }

    const assignmentMatch =
      /^(?:var\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)?\s*(?::=|=)\s*(.+)$/.exec(
        line,
      );

    if (!assignmentMatch) {
      continue;
    }

    const [, identifier, expression] = assignmentMatch;

    if (looksLikeRequestSource(expression) || containsIdentifier(expression, taintedIdentifiers)) {
      taintedIdentifiers.add(identifier);
    }

    if (looksLikeSqlInterpolation(expression) || containsIdentifier(expression, sqlInterpolatedIdentifiers)) {
      sqlInterpolatedIdentifiers.add(identifier);
    }
  }

  return {
    taintedIdentifiers,
    sqlInterpolatedIdentifiers,
  };
}

function collectHardcodedCredentialFacts(text: string): ObservedFact[] {
  return findAllMatches(
    text,
    /(?:^|\n)\s*(?:const|var)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*["'`][^"'`\n]{8,}["'`]/g,
  )
    .filter(({ matchedText }) => CREDENTIAL_IDENTIFIER_PATTERN.test(matchedText))
    .map(({ matchedText, startOffset, endOffset }) =>
      createObservedFactFromOffsets(text, {
        detector: 'go-detector',
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
  state: GoScanState,
): ObservedFact[] {
  return findCallSnippets(text, logCallPattern)
    .filter((snippet) => !REDACTION_WRAPPER_PATTERN.test(snippet.text))
    .filter(
      (snippet) =>
        SENSITIVE_LABEL_PATTERN.test(snippet.text) ||
        containsIdentifier(snippet.text, state.taintedIdentifiers),
    )
    .map((snippet) => createDetectorFact(text, 'function', 'security.sensitive-data-in-logs-and-telemetry', snippet));
}

function collectRequestPathFileReadFacts(
  text: string,
  state: GoScanState,
): ObservedFact[] {
  return findCallSnippets(text, fileReadCallPattern)
    .filter(
      (snippet) =>
        looksLikeRequestSource(snippet.text) ||
        containsIdentifier(snippet.text, state.taintedIdentifiers),
    )
    .map((snippet) => createDetectorFact(text, 'block', 'security.request-path-file-read', snippet));
}

function collectCommandExecutionFacts(
  text: string,
  state: GoScanState,
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
  state: GoScanState,
): ObservedFact[] {
  return findCallSnippets(text, sqlCallPattern)
    .filter((snippet) => !isGoFunctionDeclaration(text, snippet.startOffset))
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
  state: GoScanState,
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
  return findAllMatches(text, tlsVerificationPattern).map(
    ({ matchedText, startOffset, endOffset }) =>
      createObservedFactFromOffsets(text, {
        detector: 'go-detector',
        appliesTo: 'block',
        kind: 'security.tls-verification-disabled',
        startOffset,
        endOffset,
        text: matchedText,
        props: {},
      }),
  );
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
        detector: 'go-detector',
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
    detector: 'go-detector',
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
    /\bfmt\.Sprintf\s*\(/.test(expression) ||
    /"[^"\n]*SELECT[\s\S]*"\s*\+/.test(expression) ||
    /\+\s*"[^"\n]*"/.test(expression)
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
  return expression.match(/https?:\/\/[^\s"'`)]+/giu) ?? [];
}

function isGoFunctionDeclaration(text: string, startOffset: number): boolean {
  const lineStart = text.lastIndexOf('\n', startOffset - 1) + 1;
  const linePrefix = text.slice(lineStart, startOffset);

  return /\bfunc\b/.test(linePrefix);
}

function findFirstUnmatchedDelimiter(
  text: string,
  ...pairs: Array<[string, string]>
): string | undefined {
  let quote: '"' | "'" | '`' | null = null;
  let escapeNext = false;
  const stack: string[] = [];
  const openToClose = new Map(pairs);
  const closeToOpen = new Map(pairs.map(([open, close]) => [close, open]));

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    const previous = index > 0 ? text[index - 1] : '';

    if (quote) {
      if (escapeNext) {
        escapeNext = false;
        continue;
      }

      if (character === '\\' && quote !== '`') {
        escapeNext = true;
        continue;
      }

      if (character === quote) {
        quote = null;
      }

      continue;
    }

    if (previous === '/' && character === '/') {
      while (index < text.length && text[index] !== '\n') {
        index += 1;
      }
      continue;
    }

    if (character === '"' || character === "'" || character === '`') {
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
