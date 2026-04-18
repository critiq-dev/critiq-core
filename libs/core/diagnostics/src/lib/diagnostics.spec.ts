import {
  aggregateDiagnostics,
  BUILT_IN_DIAGNOSTIC_CODES,
  compareDiagnostics,
  createDiagnostic,
  createJsonPointer,
  createSourcePosition,
  createSourceSpan,
  DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
  DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
  DIAGNOSTIC_CODE_SEMANTIC_VALIDATION_INVALID,
  DIAGNOSTIC_CODE_YAML_MAPPING_DUPLICATE_KEY,
  DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
  DIAGNOSTIC_SEVERITY_ERROR,
  DIAGNOSTIC_SEVERITY_INFO,
  DIAGNOSTIC_SEVERITY_VALUES,
  DIAGNOSTIC_SEVERITY_WARNING,
  escapeJsonPointerSegment,
  formatDiagnosticsAsJson,
  formatDiagnosticsForTerminal,
  sortDiagnostics,
} from './diagnostics';

describe('diagnostics contracts', () => {
  it('creates source positions and spans with the expected shape', () => {
    const span = createSourceSpan({
      uri: 'file:///rules/example.yaml',
      start: createSourcePosition(2, 3),
      end: createSourcePosition(2, 14),
    });

    expect(span).toEqual({
      uri: 'file:///rules/example.yaml',
      start: {
        line: 2,
        column: 3,
      },
      end: {
        line: 2,
        column: 14,
      },
    });
  });

  it('creates diagnostics with only required fields and defaults severity to error', () => {
    expect(
      createDiagnostic({
        code: DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
        message: 'Unexpected token.',
      }),
    ).toEqual({
      code: DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
      severity: DIAGNOSTIC_SEVERITY_ERROR,
      message: 'Unexpected token.',
      summary: undefined,
      sourceSpan: undefined,
      jsonPointer: undefined,
      details: undefined,
    });
  });

  it('preserves optional source spans, pointers, and details', () => {
    const diagnostic = createDiagnostic({
      code: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
      severity: DIAGNOSTIC_SEVERITY_WARNING,
      message: 'Rule contract validation failed.',
      summary: 'Invalid metadata.id value.',
      sourceSpan: createSourceSpan({
        uri: 'file:///rules/example.yaml',
        start: createSourcePosition(4, 1),
        end: createSourcePosition(4, 24),
      }),
      jsonPointer: createJsonPointer(['metadata', 'id']),
      details: {
        expected: 'dotted slug',
        received: 'bad id',
      },
    });

    expect(diagnostic).toEqual({
      code: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
      severity: DIAGNOSTIC_SEVERITY_WARNING,
      message: 'Rule contract validation failed.',
      summary: 'Invalid metadata.id value.',
      sourceSpan: {
        uri: 'file:///rules/example.yaml',
        start: {
          line: 4,
          column: 1,
        },
        end: {
          line: 4,
          column: 24,
        },
      },
      jsonPointer: '/metadata/id',
      details: {
        expected: 'dotted slug',
        received: 'bad id',
      },
    });
  });

  it('escapes JSON pointer segments using RFC 6901 rules', () => {
    expect(escapeJsonPointerSegment('foo/bar~baz')).toBe('foo~1bar~0baz');
    expect(createJsonPointer(['emit', 'message/title', 0, '~detail'])).toBe(
      '/emit/message~1title/0/~0detail',
    );
  });

  it('uses the root pointer when no segments are provided', () => {
    expect(createJsonPointer([])).toBe('/');
  });

  it('exports the built-in diagnostic code catalog and severity values', () => {
    expect(BUILT_IN_DIAGNOSTIC_CODES).toEqual({
      yamlSyntaxInvalid: DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
      yamlMappingDuplicateKey: DIAGNOSTIC_CODE_YAML_MAPPING_DUPLICATE_KEY,
      contractValidationInvalid: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
      semanticValidationInvalid: DIAGNOSTIC_CODE_SEMANTIC_VALIDATION_INVALID,
      runtimeInternalError: DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
    });
    expect(DIAGNOSTIC_SEVERITY_VALUES).toEqual(['error', 'warning', 'info']);
  });

  it('sorts diagnostics deterministically by location, severity, code, and message', () => {
    const diagnostics = [
      createDiagnostic({
        code: DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
        severity: DIAGNOSTIC_SEVERITY_INFO,
        message: 'Zed message.',
      }),
      createDiagnostic({
        code: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
        severity: DIAGNOSTIC_SEVERITY_WARNING,
        message: 'Later location.',
        sourceSpan: createSourceSpan({
          uri: 'file:///b.yaml',
          start: createSourcePosition(1, 1),
          end: createSourcePosition(1, 2),
        }),
      }),
      createDiagnostic({
        code: DIAGNOSTIC_CODE_YAML_MAPPING_DUPLICATE_KEY,
        severity: DIAGNOSTIC_SEVERITY_WARNING,
        message: 'Earlier location.',
        sourceSpan: createSourceSpan({
          uri: 'file:///a.yaml',
          start: createSourcePosition(1, 1),
          end: createSourcePosition(1, 2),
        }),
      }),
      createDiagnostic({
        code: DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
        severity: DIAGNOSTIC_SEVERITY_ERROR,
        message: 'Alpha message.',
      }),
    ];

    expect(
      sortDiagnostics(diagnostics).map((diagnostic) => diagnostic.message),
    ).toEqual([
      'Alpha message.',
      'Zed message.',
      'Earlier location.',
      'Later location.',
    ]);
  });

  it('orders severities predictably when locations match', () => {
    const location = createSourceSpan({
      uri: 'file:///same.yaml',
      start: createSourcePosition(1, 1),
      end: createSourcePosition(1, 2),
    });

    const errorDiagnostic = createDiagnostic({
      code: DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
      severity: DIAGNOSTIC_SEVERITY_ERROR,
      message: 'error',
      sourceSpan: location,
    });
    const warningDiagnostic = createDiagnostic({
      code: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
      severity: DIAGNOSTIC_SEVERITY_WARNING,
      message: 'warning',
      sourceSpan: location,
    });

    expect(compareDiagnostics(errorDiagnostic, warningDiagnostic)).toBeLessThan(
      0,
    );
  });

  it('aggregates diagnostics into a sorted copy without mutating the original array', () => {
    const input = [
      createDiagnostic({
        code: DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
        severity: DIAGNOSTIC_SEVERITY_WARNING,
        message: 'second',
      }),
      createDiagnostic({
        code: DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
        severity: DIAGNOSTIC_SEVERITY_ERROR,
        message: 'first',
      }),
    ];

    const output = aggregateDiagnostics(input);

    expect(output.map((diagnostic) => diagnostic.message)).toEqual([
      'first',
      'second',
    ]);
    expect(input.map((diagnostic) => diagnostic.message)).toEqual([
      'second',
      'first',
    ]);
  });

  it('formats JSON without dropping structured detail', () => {
    const diagnostic = createDiagnostic({
      code: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
      message: 'Invalid document.',
      sourceSpan: createSourceSpan({
        uri: 'file:///rules/example.yaml',
        start: createSourcePosition(5, 2),
        end: createSourcePosition(5, 10),
      }),
      jsonPointer: createJsonPointer(['match', 'all', 0]),
      details: {
        expected: 'non-empty array',
      },
    });

    expect(formatDiagnosticsAsJson([diagnostic])).toBe(`[
  {
    "code": "contract.validation.invalid",
    "severity": "error",
    "message": "Invalid document.",
    "sourceSpan": {
      "uri": "file:///rules/example.yaml",
      "start": {
        "line": 5,
        "column": 2
      },
      "end": {
        "line": 5,
        "column": 10
      }
    },
    "jsonPointer": "/match/all/0",
    "details": {
      "expected": "non-empty array"
    }
  }
]
`);
  });

  it('formats terminal text with severity, code, message, location, and pointer', () => {
    const output = formatDiagnosticsForTerminal([
      createDiagnostic({
        code: DIAGNOSTIC_CODE_SEMANTIC_VALIDATION_INVALID,
        severity: DIAGNOSTIC_SEVERITY_WARNING,
        message: 'Capture is not reachable.',
        summary: 'Unknown capture name.',
        sourceSpan: createSourceSpan({
          uri: 'file:///rules/example.yaml',
          start: createSourcePosition(12, 7),
          end: createSourcePosition(12, 22),
        }),
        jsonPointer: createJsonPointer(['emit', 'message', 'detail']),
        details: {
          capture: 'foo',
        },
      }),
    ]);

    expect(output)
      .toBe(`WARNING [semantic.validation.invalid] Capture is not reachable.
  Summary: Unknown capture name.
  Location: file:///rules/example.yaml:12:7
  Pointer: /emit/message/detail
  Details: {
    "capture": "foo"
  }`);
  });

  it('renders diagnostics without spans or pointers cleanly', () => {
    expect(
      formatDiagnosticsForTerminal([
        createDiagnostic({
          code: DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
          severity: DIAGNOSTIC_SEVERITY_INFO,
          message: 'Recovered from transient error.',
        }),
      ]),
    ).toBe('INFO [runtime.internal.error] Recovered from transient error.');
  });
});
