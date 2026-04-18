# @critiq/core-ir

`@critiq/core-ir` owns the stable internal rule representation used by runtime
evaluation. It accepts already loaded, contract-valid, semantic-valid rule
documents from `@critiq/core-rules-dsl` and normalizes them into canonical
plain data plus a deterministic rule hash.

Allowed dependencies: `type:core`, `type:util`

## Public API

- `normalizeRuleDocument(validatedRuleDocument)`
- `NormalizedRule`
- `NormalizedScope`
- `NormalizedPredicate`
- `NormalizedEmitSpec`
- `NormalizeRuleDocumentResult`

## Normalization Guarantees

- language aliases are canonicalized: `ts -> typescript`, `js -> javascript`
- tags and path globs are trimmed, deduped, and sorted
- `changedLinesOnly` defaults to `false`
- the canonical `ruleHash` is derived from normalized semantic content only
- source/debug metadata is returned in a sidecar and is excluded from hashing

## Example

```ts
import { normalizeRuleDocument } from '@critiq/core-ir';
import { loadRuleText, validateLoadedRuleDocument } from '@critiq/core-rules-dsl';

const loaded = loadRuleText(ruleText, 'file:///rules/no-console.yaml');

if (loaded.success) {
  const validated = validateLoadedRuleDocument(loaded.data);

  if (validated.success) {
    const normalized = normalizeRuleDocument(validated.data);
    console.log(normalized.rule.ruleHash);
  }
}
```

Commands:

- `npm run nx -- build ir`
- `npm run nx -- test ir`
- `npm run nx -- lint ir`
