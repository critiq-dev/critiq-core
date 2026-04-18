# @critiq/core-finding-schema

The canonical v0 finding contract for Critiq OSS. This package defines the stable `FindingV0` output schema, validates unknown input at runtime, and publishes a checked-in JSON Schema artifact for external consumers.

## Exports

- `FindingV0` and supporting nested contract types
- `FindingCategory`, `FindingSeverity`, `FindingConfidence`
- `findingV0Schema`
- `findingV0JsonSchema`
- `validateFinding()`
- `assertValidFinding()`
- `isFinding()`
- `FINDING_V0_SCHEMA_VERSION`

Schema version: `finding/v0`

## Example

```ts
import { validateFinding } from '@critiq/core-finding-schema';

const result = validateFinding({
  schemaVersion: 'finding/v0',
  findingId: '6d86f84f-3f5c-4bc3-9f5d-8e24d441f8d7',
  rule: { id: 'ts.security.no-sql-interpolation' },
  title: 'SQL query built via string concatenation',
  summary: 'Use query placeholders instead of string interpolation.',
  category: 'security.injection',
  severity: 'high',
  confidence: 0.95,
  locations: {
    primary: {
      path: 'src/app/service.ts',
      startLine: 17,
      startColumn: 5,
      endLine: 17,
      endColumn: 28,
    },
  },
  evidence: [
    {
      kind: 'ast',
      label: 'matched-call',
      path: 'src/app/service.ts',
      excerpt: 'console.log("hello")',
      range: {
        startLine: 17,
        startColumn: 5,
        endLine: 17,
        endColumn: 28,
      },
    },
  ],
  fingerprints: {
    primary: 'sha256:abc123',
  },
  provenance: {
    engineKind: 'dsl-runtime',
    engineVersion: '0.1.0',
    generatedAt: '2026-04-06T12:00:00.000Z',
  },
});

if (!result.success) {
  console.error(result.issues);
}
```

Supported values now include dot-delimited categories such as
`security.injection`, `critical` severity, and either qualitative or numeric
confidence values.

## Commands

- `npm run nx -- run finding-schema:generate-schema`
- `npm run nx -- build finding-schema`
- `npm run nx -- test finding-schema`
- `npm run nx -- lint finding-schema`
