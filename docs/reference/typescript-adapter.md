# TypeScript Adapter Reference

`@critiq/adapter-typescript` is the example ESTree adapter used by the harness
and starter pack.

## Entry Point

```ts
analyzeTypeScriptFile(path, text)
```

## Supported Inputs

- `.ts`
- `.tsx`
- `.js`
- `.jsx`

## Output Guarantees

Success returns a core `AnalyzedFile` with:

- deterministic node ordering
- deterministic node ids derived from node kind and range
- ESTree node kinds
- parent/child links
- line/column ranges
- optional `semantics.controlFlow` data with:
  - `functions`
  - `blocks`
  - `edges`
  - `facts`

## Stable v0 Property Paths

- `text`
- `callee.object.text`
- `callee.property.text`
- `argument.text`

Anything outside the documented property-path surface is adapter-internal and
not part of the compatibility guarantee.

## v1 Semantic Facts

The TypeScript adapter currently emits control-flow facts for:

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
