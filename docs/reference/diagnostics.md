# Diagnostics Reference

`@critiq/core-diagnostics` defines the shared source-aware diagnostics contract for parsing and validation.

## Core Types

- `SourcePosition`: 1-based `{ line, column }`
- `SourceSpan`: `{ uri, start, end }`
- `JsonPointer`: RFC 6901 pointer string
- `Diagnostic`: structured diagnostic object with `code`, `severity`, and `message`

Optional diagnostic fields:

- `summary`
- `sourceSpan`
- `jsonPointer`
- `details`

## Severity Values

- `error`
- `warning`
- `info`

## Built-in Diagnostic Codes

- `yaml.syntax.invalid`
- `yaml.mapping.duplicate-key`
- `contract.validation.invalid`
- `semantic.validation.invalid`
- `runtime.internal.error`

## JSON Pointer Rules

Pointers are RFC 6901 compatible:

- `/` is the root pointer
- `~` escapes as `~0`
- `/` escapes as `~1`

Example:

```ts
createJsonPointer(['emit', 'message/title', '~detail']);
// => /emit/message~1title/~0detail
```

## Deterministic Ordering

Diagnostics sort in this exact order:

1. `sourceSpan.uri`
2. `sourceSpan.start.line`
3. `sourceSpan.start.column`
4. `sourceSpan.end.line`
5. `sourceSpan.end.column`
6. severity rank: `error`, `warning`, `info`
7. `code`
8. `message`

Diagnostics without a source span sort before located diagnostics because their location fields compare as empty/zero values.

## JSON Output Example

```json
[
  {
    "code": "contract.validation.invalid",
    "severity": "error",
    "message": "Rule document is invalid.",
    "sourceSpan": {
      "uri": "file:///rules/example.yaml",
      "start": {
        "line": 4,
        "column": 1
      },
      "end": {
        "line": 4,
        "column": 12
      }
    },
    "jsonPointer": "/metadata/id",
    "details": {
      "expected": "dotted slug"
    }
  }
]
```

## Terminal Output Example

```text
ERROR [contract.validation.invalid] Rule document is invalid.
  Location: file:///rules/example.yaml:4:1
  Pointer: /metadata/id
  Details: {
    "expected": "dotted slug"
  }
```
