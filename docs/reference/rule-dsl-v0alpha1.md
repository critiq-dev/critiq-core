# Rule DSL v0alpha1

`RuleDocumentV0Alpha1` is the canonical public authoring contract for Critiq rules. It is product-oriented, deterministic, and intentionally decoupled from parser-specific syntax and runtime internals.

## Version

- `apiVersion`: `critiq.dev/v1alpha1`
- `kind`: `Rule`

## Required Top-Level Sections

- `apiVersion`
- `kind`
- `metadata`
- `scope`
- `match`
- `emit`

## Metadata

Required:

- `metadata.id`
- `metadata.title`
- `metadata.summary`

Optional:

- `metadata.rationale`
- `metadata.tags`
- `metadata.status`
- `metadata.stability`
- `metadata.appliesTo`

`metadata.id` must be a non-empty string at the contract layer. The dotted-slug
format used by shipped rules, such as `ts.logging.no-console-log`, is enforced
by semantic validation.

## Scope

Supported fields:

- `languages`
- `paths.include`
- `paths.exclude`
- `changedLinesOnly`

Allowed languages:

- `typescript`
- `javascript`
- `ts`
- `js`
- `python`
- `go`
- `all`

## Match Grammar

Supported condition nodes:

- `all`
- `any`
- `not`
- `node`
- `ancestor`
- `fact`

Supported comparison operators:

- `equals`
- `in`
- `matches`
- `exists`

## Minimal Example

```json
{
  "apiVersion": "critiq.dev/v1alpha1",
  "kind": "Rule",
  "metadata": {
    "id": "ts.logging.no-console-log",
    "title": "Avoid console.log in production code",
    "summary": "Production code must use the structured logger."
  },
  "scope": {
    "languages": ["typescript"]
  },
  "match": {
    "node": {
      "kind": "CallExpression"
    }
  },
  "emit": {
    "finding": {
      "category": "maintainability",
      "severity": "low",
      "confidence": "high"
    },
    "message": {
      "title": "Avoid console.log in production code",
      "summary": "Use the team logger instead of console.log."
    }
  }
}
```

## Full Example

```json
{
  "apiVersion": "critiq.dev/v1alpha1",
  "kind": "Rule",
  "metadata": {
    "id": "ts.logging.no-console-log",
    "title": "Avoid console.log in production code",
    "summary": "Production code must use the structured logger.",
    "rationale": "Console logging bypasses standard logging controls.",
    "tags": ["logging", "maintainability"],
    "status": "experimental"
  },
  "scope": {
    "languages": ["typescript", "javascript"],
    "paths": {
      "include": ["src/**"],
      "exclude": ["**/*.test.*", "**/fixtures/**"]
    },
    "changedLinesOnly": true
  },
  "match": {
    "all": [
      {
        "node": {
          "kind": "CallExpression",
          "bind": "call",
          "where": [
            {
              "path": "callee.object.text",
              "equals": "console"
            },
            {
              "path": "callee.property.text",
              "equals": "log"
            }
          ]
        }
      },
      {
        "not": {
          "ancestor": {
            "kind": "CatchClause"
          }
        }
      }
    ]
  },
  "emit": {
    "finding": {
      "category": "maintainability",
      "severity": "low",
      "confidence": "high",
      "tags": ["logging"]
    },
    "message": {
      "title": "Avoid console.log in production code",
      "summary": "Use the team logger instead of console.log.",
      "detail": "Found `${captures.call.text}` in `${file.path}`."
    },
    "remediation": {
      "summary": "Replace this call with `logger.info` or `logger.debug`."
    }
  }
}
```
