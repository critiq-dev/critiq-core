# Finding Schema v0

`FindingV0` is the canonical portable output contract for Critiq OSS findings. All deterministic engines, adapters, and future hosted integrations should converge on this shape.

## Version

- `schemaVersion`: `finding/v0`

## Enums

- `category`: dot-delimited categories such as `security.injection` or
  `quality.structure`
- `severity`: `low`, `medium`, `high`, `critical`
- `confidence`: `low`, `medium`, `high`, or a numeric score between `0` and `1`

## Required Fields

- `schemaVersion`
- `findingId`
- `rule.id`
- `title`
- `summary`
- `category`
- `severity`
- `confidence`
- `locations.primary`
- `evidence`
- `fingerprints.primary`
- `provenance.engineKind`
- `provenance.engineVersion`
- `provenance.generatedAt`

## Optional Fields

- `rule.name`
- `rule.version`
- `tags`
- `locations.related`
- `remediation`
- `fingerprints.logical`
- `provenance.rulePack`
- `attributes`

## Minimal Example

```json
{
  "schemaVersion": "finding/v0",
  "findingId": "6d86f84f-3f5c-4bc3-9f5d-8e24d441f8d7",
  "rule": {
    "id": "ts.logging.no-console-log"
  },
  "title": "Avoid console.log in production code",
  "summary": "Use the team logger instead of console.log.",
  "category": "maintainability",
  "severity": "low",
  "confidence": "high",
  "locations": {
    "primary": {
      "path": "src/app/service.ts",
      "startLine": 17,
      "startColumn": 5,
      "endLine": 17,
      "endColumn": 28
    }
  },
  "evidence": [
    {
      "kind": "ast",
      "label": "matched-call",
      "path": "src/app/service.ts",
      "excerpt": "console.log(\"hello\")",
      "range": {
        "startLine": 17,
        "startColumn": 5,
        "endLine": 17,
        "endColumn": 28
      }
    }
  ],
  "fingerprints": {
    "primary": "sha256:0f5f4d20f7e8f53d4fb01d6d8d09b6c38b738d8a6f3184b31d4b2d6ecf65e123"
  },
  "provenance": {
    "engineKind": "dsl-runtime",
    "engineVersion": "0.1.0",
    "generatedAt": "2026-04-06T12:00:00.000Z"
  }
}
```

## Rich Example

```json
{
  "schemaVersion": "finding/v0",
  "findingId": "b9427a0b-1f3b-4a27-bf61-95a4b4fb55fd",
  "rule": {
    "id": "ts.logging.no-console-log",
    "name": "Avoid console.log in production code",
    "version": "0.1.0"
  },
  "title": "Avoid console.log in production code",
  "summary": "Use the team logger instead of console.log.",
  "category": "maintainability",
  "severity": "low",
  "confidence": "high",
  "tags": ["logging", "maintainability"],
  "locations": {
    "primary": {
      "path": "src/app/service.ts",
      "startLine": 17,
      "startColumn": 5,
      "endLine": 17,
      "endColumn": 28
    },
    "related": [
      {
        "path": "src/app/logger.ts",
        "startLine": 4,
        "startColumn": 1,
        "endLine": 8,
        "endColumn": 2
      }
    ]
  },
  "evidence": [
    {
      "kind": "ast",
      "label": "matched-call",
      "path": "src/app/service.ts",
      "excerpt": "console.log(\"hello\")",
      "range": {
        "startLine": 17,
        "startColumn": 5,
        "endLine": 17,
        "endColumn": 28
      }
    }
  ],
  "remediation": {
    "summary": "Replace this call with logger.info or logger.debug."
  },
  "fingerprints": {
    "primary": "sha256:1f5f4d20f7e8f53d4fb01d6d8d09b6c38b738d8a6f3184b31d4b2d6ecf65e456",
    "logical": "sha256:2f5f4d20f7e8f53d4fb01d6d8d09b6c38b738d8a6f3184b31d4b2d6ecf65e789"
  },
  "provenance": {
    "engineKind": "dsl-runtime",
    "engineVersion": "0.1.0",
    "rulePack": "critiq/starter-pack",
    "generatedAt": "2026-04-06T12:00:00.000Z"
  },
  "attributes": {
    "team": "platform",
    "triage": {
      "owner": "logging",
      "count": 1
    },
    "suppressed": false
  }
}
```
