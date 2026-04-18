# @critiq/adapter-typescript

`@critiq/adapter-typescript` is the reference ESTree-backed adapter for `.ts`,
`.tsx`, `.js`, and `.jsx` files.

## Public API

- `analyzeTypeScriptFile(path, text): TypeScriptAnalysisResult`

Success returns a core `AnalyzedFile`. Failure returns structured diagnostics
instead of raw parser exceptions.

## v1 Semantic Output

Successful analysis now also exposes `semantics.controlFlow` with:

- `functions`
- `blocks`
- `edges`
- `facts`

The current fact set covers:

- implicit undefined returns
- missing default dispatch paths
- unreachable statements after `return` or `throw`
- swallowed errors in `catch`
- missing error context in `catch`

Recognized error sinks:

- `console.error`
- `console.warn`
- `logger.error`
- `logger.warn`
- `captureException`

## v0 Property Projection

The adapter intentionally exposes a small stable property-path surface:

- `text`
- `callee.object.text`
- `callee.property.text`
- `argument.text`
- identifier and member-expression text used by the starter pack

## Non-Goals

- type checking
- symbol resolution
- cross-file analysis
- code fixes

Allowed dependencies: `type:core`, `type:util`
