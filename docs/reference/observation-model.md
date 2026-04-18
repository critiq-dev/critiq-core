# Observation Model Reference

`CRQ-OSS-08` introduces the language-agnostic runtime input model in
`@critiq/core-rules-engine`.

## Core Types

- `AnalyzedFile`
  - `path`
  - `language`
  - `text`
  - `nodes`
  - optional `changedRanges`
- `ObservedNode`
  - `id`
  - `kind`
  - `range`
  - optional `text`
  - optional `parentId`
  - optional `childrenIds`
  - `props`
- `ObservedRange` and `DiffRange`
  - `startLine`
  - `startColumn`
  - `endLine`
  - `endColumn`

## Property Rules

- `props` must stay JSON-like
- line and column coordinates are 1-based
- `ObservedNode.id` must be stable within the file
- parent and child relationships are expressed only through ids

## Deterministic Ordering

Runtime evaluation orders nodes by:

1. `range.startLine`
2. `range.startColumn`
3. `range.endLine`
4. `range.endColumn`
5. `id`

Use `sortObservedNodes(...)` to apply that ordering.

## Runtime Helpers

- `getNodeProperty(node, 'a.b.c')`
- `getAncestorNodes(analyzedFile, node)`
- range intersection helpers are used internally for changed-line filtering
