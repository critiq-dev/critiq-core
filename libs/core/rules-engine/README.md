# @critiq/core-rules-engine

`@critiq/core-rules-engine` owns the language-agnostic runtime pipeline that
evaluates normalized rules against analyzed files and builds validated
`FindingV0` outputs.

Allowed dependencies: `type:core`, `type:util`

## Public API

- observation contracts:
  - `AnalyzedFile`
  - `ObservedNode`
  - `ObservedRange`
  - `DiffRange`
  - `CaptureMap`
  - `EvaluationMatch`
- runtime helpers:
  - `sortObservedNodes(...)`
  - `getNodeProperty(...)`
  - `getAncestorNodes(...)`
- rule execution:
  - `evaluateRuleApplicability(...)`
  - `evaluateRule(...)`
- rendering and findings:
  - `renderMessageTemplate(...)`
  - `buildFinding(...)`

## Runtime Guarantees

- observed nodes are evaluated in deterministic range order
- applicability checks short-circuit language, path, and changed-file skips
- predicate evaluation supports `all`, `any`, `not`, `node`, and `ancestor`
- template rendering supports only the v0 safe variable set
- `buildFinding(...)` validates every emitted finding through
  `@critiq/core-finding-schema`

## Example

```ts
import { normalizeRuleDocument } from '@critiq/core-ir';
import { buildFinding, evaluateRule } from '@critiq/core-rules-engine';

const matches = evaluateRule(normalized.rule, analyzedFile);

for (const match of matches) {
  const result = buildFinding(normalized.rule, analyzedFile, match);

  if (result.success) {
    console.log(result.finding.findingId);
  }
}
```

Commands:

- `npm run nx -- build rules-engine`
- `npm run nx -- test rules-engine`
- `npm run nx -- lint rules-engine`
