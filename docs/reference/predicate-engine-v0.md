# Predicate Engine v0 Reference

`CRQ-OSS-10` adds deterministic predicate evaluation in
`@critiq/core-rules-engine`.

## API

- `evaluateRule(rule, analyzedFile): EvaluationMatch[]`

## Supported Predicates

- `all`
- `any`
- `not`
- `node`
- `ancestor`
- `fact`

## Supported Operators

- `equals`
- `in`
- `matches`
- `exists`

## Evaluation Rules

- candidate nodes are evaluated in deterministic node order
- `node` predicates evaluate against the current candidate node
- `ancestor` predicates walk parent links from nearest to farthest ancestor
- fact predicates evaluate against adapter-provided semantic facts
- `all` merges captures left to right
- `any` returns the first successful branch in canonical order
- `not` succeeds only when its child fails and contributes no captures
- v1 rejects rules that mix `fact` predicates with `node` or `ancestor`
  predicates in the same match tree

## Match Output

Each `EvaluationMatch` includes:

- `nodeId`
- `nodeKind`
- `range`
- `captures`
- `sortKey`

## Changed-Line Post Filter

When a normalized rule sets `changedLinesOnly`, a successful candidate match is
dropped unless the primary matched node range intersects at least one file
change range.
