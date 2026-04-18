# Normalized Rule IR Reference

`CRQ-OSS-07` introduces the canonical internal rule representation in
`@critiq/core-ir`.

## Purpose

Normalization converts a contract-valid, semantic-valid rule document into
stable plain data for deterministic evaluation and hashing.

## Main Shape

- `NormalizedRule`
  - `apiVersion`
  - `kind`
  - `ruleId`
  - `title`
  - `summary`
  - optional `rationale`
  - optional `status`
  - `tags`
  - `scope`
  - `predicate`
  - `emit`
  - `ruleHash`
- `NormalizedScope`
  - `languages`
  - `includeGlobs`
  - `excludeGlobs`
  - `changedLinesOnly`
- `NormalizedPredicate`
  - `all`
  - `any`
  - `not`
  - `node`
  - `ancestor`
  - `fact`

## Canonicalization Rules

- `ts` normalizes to `typescript`
- `js` normalizes to `javascript`
- tags are trimmed, deduped, and sorted
- include and exclude globs are trimmed, deduped, and sorted
- `changedLinesOnly` defaults to `false`
- logical child order is preserved

## Hashing

`ruleHash` is a SHA-256 digest of the canonical semantic IR only.

- source URIs are not part of the hash
- YAML formatting differences are not part of the hash
- debug/source sidecar data is not part of the hash

## Sidecar Data

`normalizeRuleDocument(...)` also returns:

- `rule`
- `ruleHash`
- `debug`
  - `uri`
  - `sourceMap`

The sidecar exists for explainability and diagnostics. It is intentionally kept
out of the hashed rule payload.
