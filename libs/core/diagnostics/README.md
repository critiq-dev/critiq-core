# @critiq/core-diagnostics

Shared contracts and rendering helpers for source-aware parser and validator diagnostics.

This package defines the reusable v0 diagnostics model used by later loader and validation stories:

- `SourcePosition`
- `SourceSpan`
- `JsonPointer`
- `Diagnostic`
- `DiagnosticSeverity`
- `DiagnosticCode`

It also exports:

- built-in severity literals and code constants
- `createSourcePosition()`
- `createSourceSpan()`
- `escapeJsonPointerSegment()`
- `createJsonPointer()`
- `createDiagnostic()`
- `compareDiagnostics()`
- `sortDiagnostics()`
- `aggregateDiagnostics()`
- `formatDiagnosticsAsJson()`
- `formatDiagnosticsForTerminal()`

## Severity model

Supported severities:

- `error`
- `warning`
- `info`

## Built-in code catalog

- `yaml.syntax.invalid`
- `yaml.mapping.duplicate-key`
- `contract.validation.invalid`
- `semantic.validation.invalid`
- `runtime.internal.error`

## Example

```ts
import {
  DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
  createDiagnostic,
  createJsonPointer,
  createSourcePosition,
  createSourceSpan,
  formatDiagnosticsForTerminal,
} from '@critiq/core-diagnostics';

const diagnostic = createDiagnostic({
  code: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
  message: 'Rule document is invalid.',
  sourceSpan: createSourceSpan({
    uri: 'file:///rules/example.yaml',
    start: createSourcePosition(4, 1),
    end: createSourcePosition(4, 12),
  }),
  jsonPointer: createJsonPointer(['metadata', 'id']),
});

console.log(formatDiagnosticsForTerminal([diagnostic]));
```

Allowed dependencies: `type:core`, `type:util`
