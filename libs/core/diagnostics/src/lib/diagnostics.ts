const diagnosticSeverityValues = ['error', 'warning', 'info'] as const;

const diagnosticSeverityRank: Record<DiagnosticSeverity, number> = {
  error: 0,
  warning: 1,
  info: 2,
};

/**
 * Enumerates the supported diagnostic severity levels.
 */
export type DiagnosticSeverity = (typeof diagnosticSeverityValues)[number];

/**
 * Exposes the supported diagnostic severity values.
 */
export const DIAGNOSTIC_SEVERITY_VALUES = diagnosticSeverityValues;

/**
 * The error severity literal.
 */
export const DIAGNOSTIC_SEVERITY_ERROR = 'error' as const;

/**
 * The warning severity literal.
 */
export const DIAGNOSTIC_SEVERITY_WARNING = 'warning' as const;

/**
 * The informational severity literal.
 */
export const DIAGNOSTIC_SEVERITY_INFO = 'info' as const;

/**
 * Built-in diagnostic code for YAML syntax failures.
 */
export const DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID =
  'yaml.syntax.invalid' as const;

/**
 * Built-in diagnostic code for duplicate YAML mapping keys.
 */
export const DIAGNOSTIC_CODE_YAML_MAPPING_DUPLICATE_KEY =
  'yaml.mapping.duplicate-key' as const;

/**
 * Built-in diagnostic code for contract validation failures.
 */
export const DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID =
  'contract.validation.invalid' as const;

/**
 * Built-in diagnostic code for semantic validation failures.
 */
export const DIAGNOSTIC_CODE_SEMANTIC_VALIDATION_INVALID =
  'semantic.validation.invalid' as const;

/**
 * Built-in diagnostic code for internal runtime failures.
 */
export const DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR =
  'runtime.internal.error' as const;

/**
 * Enumerates the built-in diagnostic codes shipped in v0.
 */
export const BUILT_IN_DIAGNOSTIC_CODES = {
  yamlSyntaxInvalid: DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
  yamlMappingDuplicateKey: DIAGNOSTIC_CODE_YAML_MAPPING_DUPLICATE_KEY,
  contractValidationInvalid: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
  semanticValidationInvalid: DIAGNOSTIC_CODE_SEMANTIC_VALIDATION_INVALID,
  runtimeInternalError: DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
} as const;

/**
 * Represents the built-in diagnostic code literals.
 */
export type BuiltInDiagnosticCode =
  (typeof BUILT_IN_DIAGNOSTIC_CODES)[keyof typeof BUILT_IN_DIAGNOSTIC_CODES];

/**
 * Represents a stable diagnostic code. Future packages may add new namespaced
 * codes without breaking this contract.
 */
export type DiagnosticCode = BuiltInDiagnosticCode | (string & {});

/**
 * Represents a 1-based source position.
 */
export interface SourcePosition {
  line: number;
  column: number;
}

/**
 * Represents a 1-based source span within a concrete file or URI.
 */
export interface SourceSpan {
  uri: string;
  start: SourcePosition;
  end: SourcePosition;
}

/**
 * Represents an RFC 6901 JSON Pointer.
 */
export type JsonPointer = string;

/**
 * Represents a machine-readable bag of diagnostic details.
 */
export type DiagnosticDetails = Record<string, unknown>;

/**
 * Represents a single structured diagnostic.
 */
export interface Diagnostic {
  code: DiagnosticCode;
  severity: DiagnosticSeverity;
  message: string;
  summary?: string;
  sourceSpan?: SourceSpan;
  jsonPointer?: JsonPointer;
  details?: DiagnosticDetails;
}

/**
 * Represents the minimal constructor input for a source span.
 */
export interface CreateSourceSpanInput {
  uri: string;
  start: SourcePosition;
  end: SourcePosition;
}

/**
 * Represents the minimal constructor input for a diagnostic.
 */
export interface CreateDiagnosticInput {
  code: DiagnosticCode;
  message: string;
  severity?: DiagnosticSeverity;
  summary?: string;
  sourceSpan?: SourceSpan;
  jsonPointer?: JsonPointer;
  details?: DiagnosticDetails;
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`Expected ${label} to be a positive integer.`);
  }
}

function assertNonEmptyString(value: string, label: string): void {
  if (value.trim().length === 0) {
    throw new Error(`Expected ${label} to be a non-empty string.`);
  }
}

function assertSeverity(value: DiagnosticSeverity): void {
  if (!diagnosticSeverityValues.includes(value)) {
    throw new Error(`Unsupported diagnostic severity "${value}".`);
  }
}

/**
 * Creates a validated 1-based source position.
 */
export function createSourcePosition(
  line: number,
  column: number,
): SourcePosition {
  assertPositiveInteger(line, 'line');
  assertPositiveInteger(column, 'column');

  return {
    line,
    column,
  };
}

/**
 * Creates a validated source span.
 */
export function createSourceSpan(input: CreateSourceSpanInput): SourceSpan {
  assertNonEmptyString(input.uri, 'uri');
  assertPositiveInteger(input.start.line, 'start.line');
  assertPositiveInteger(input.start.column, 'start.column');
  assertPositiveInteger(input.end.line, 'end.line');
  assertPositiveInteger(input.end.column, 'end.column');

  return {
    uri: input.uri,
    start: {
      line: input.start.line,
      column: input.start.column,
    },
    end: {
      line: input.end.line,
      column: input.end.column,
    },
  };
}

/**
 * Escapes a JSON Pointer segment according to RFC 6901.
 */
export function escapeJsonPointerSegment(segment: string | number): string {
  return String(segment).split('~').join('~0').split('/').join('~1');
}

/**
 * Creates a JSON Pointer from path segments.
 */
export function createJsonPointer(
  segments: readonly (string | number)[],
): JsonPointer {
  if (segments.length === 0) {
    return '/';
  }

  return `/${segments.map(escapeJsonPointerSegment).join('/')}`;
}

/**
 * Creates a validated diagnostic and defaults severity to `error`.
 */
export function createDiagnostic(input: CreateDiagnosticInput): Diagnostic {
  assertNonEmptyString(String(input.code), 'code');
  assertNonEmptyString(input.message, 'message');

  const severity = input.severity ?? DIAGNOSTIC_SEVERITY_ERROR;

  assertSeverity(severity);

  if (input.summary !== undefined) {
    assertNonEmptyString(input.summary, 'summary');
  }

  return {
    code: input.code,
    severity,
    message: input.message,
    summary: input.summary,
    sourceSpan: input.sourceSpan,
    jsonPointer: input.jsonPointer,
    details: input.details,
  };
}

function compareNullableStrings(left?: string, right?: string): number {
  return (left ?? '').localeCompare(right ?? '');
}

function compareNumbers(left: number, right: number): number {
  return left - right;
}

/**
 * Compares diagnostics using the package's deterministic ordering contract.
 */
export function compareDiagnostics(left: Diagnostic, right: Diagnostic): number {
  const leftSpan = left.sourceSpan;
  const rightSpan = right.sourceSpan;

  const locationComparisons = [
    compareNullableStrings(leftSpan?.uri, rightSpan?.uri),
    compareNumbers(leftSpan?.start.line ?? 0, rightSpan?.start.line ?? 0),
    compareNumbers(leftSpan?.start.column ?? 0, rightSpan?.start.column ?? 0),
    compareNumbers(leftSpan?.end.line ?? 0, rightSpan?.end.line ?? 0),
    compareNumbers(leftSpan?.end.column ?? 0, rightSpan?.end.column ?? 0),
  ];

  for (const comparison of locationComparisons) {
    if (comparison !== 0) {
      return comparison;
    }
  }

  // This order is fixed so every caller gets the same stable output regardless
  // of insertion order when multiple diagnostics share a location.
  const severityComparison =
    diagnosticSeverityRank[left.severity] - diagnosticSeverityRank[right.severity];

  if (severityComparison !== 0) {
    return severityComparison;
  }

  const codeComparison = String(left.code).localeCompare(String(right.code));

  if (codeComparison !== 0) {
    return codeComparison;
  }

  return left.message.localeCompare(right.message);
}

/**
 * Returns a sorted copy of diagnostics without mutating the input array.
 */
export function sortDiagnostics(
  diagnostics: readonly Diagnostic[],
): Diagnostic[] {
  return [...diagnostics].sort(compareDiagnostics);
}

/**
 * Aggregates diagnostics into a deterministic sorted array.
 */
export function aggregateDiagnostics(
  diagnostics: readonly Diagnostic[],
): Diagnostic[] {
  return sortDiagnostics(diagnostics);
}

/**
 * Formats diagnostics as stable pretty JSON.
 */
export function formatDiagnosticsAsJson(
  diagnostics: readonly Diagnostic[],
): string {
  return `${JSON.stringify(sortDiagnostics(diagnostics), null, 2)}\n`;
}

function formatLocation(sourceSpan?: SourceSpan): string | undefined {
  if (!sourceSpan) {
    return undefined;
  }

  return `${sourceSpan.uri}:${sourceSpan.start.line}:${sourceSpan.start.column}`;
}

/**
 * Formats diagnostics as deterministic terminal-friendly plain text.
 */
export function formatDiagnosticsForTerminal(
  diagnostics: readonly Diagnostic[],
): string {
  return sortDiagnostics(diagnostics)
    .map((diagnostic) => {
      const location = formatLocation(diagnostic.sourceSpan);
      const lines = [
        `${diagnostic.severity.toUpperCase()} [${diagnostic.code}] ${diagnostic.message}`,
      ];

      if (diagnostic.summary) {
        lines.push(`  Summary: ${diagnostic.summary}`);
      }

      if (location) {
        lines.push(`  Location: ${location}`);
      }

      if (diagnostic.jsonPointer) {
        lines.push(`  Pointer: ${diagnostic.jsonPointer}`);
      }

      if (diagnostic.details) {
        lines.push(
          `  Details: ${JSON.stringify(diagnostic.details, null, 2).split('\n').join('\n  ')}`,
        );
      }

      return lines.join('\n');
    })
    .join('\n\n');
}
