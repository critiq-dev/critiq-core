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

- always-true or always-false flow-control conditions
- blocking sync Node-style calls inside async functions
- direct async calls dropped without `await` inside async functions
- implicit undefined returns
- incorrect boolean logic on same-value comparison chains
- inefficient membership lookups and key-projection checks
- large-function and deep-nesting structural thresholds
- large payload reads without streaming heuristics
- long-lived collection growth and retained large payload assignments
- missing default dispatch paths
- missing `fetch`/axios timeout configuration on external calls
- missing request timeout or retry protection on `fetch` and axios-style calls
- nested loops in one function
- nested request-derived property access without existence checks
- nullable local aliases dereferenced without a positive guard
- mutations of shared state after an `await` boundary
- off-by-one index loop boundaries against `.length`
- optional local aliases used in binary expressions without fallback normalization
- repeated recognized expensive computations in the same block
- render-path `useState` misuse in React-style components
- sequential independent awaited calls in the same block
- token or session aliases from external input used without same-function validation
- floating promise chains without explicit rejection handling
- top-level hardcoded config-like literals
- unchecked `Map#get(...)` and keyed object reads without local presence checks
- untrusted input passed into `RegExp` or `URL` construction without validation
- unreachable statements after `return` or `throw`
- swallowed errors in `catch`
- missing error context in `catch`
- magic numbers or magic strings in logic expressions
- recognized deserializers consuming external input directly

Recognized error sinks:

- `console.error`
- `console.warn`
- `logger.error`
- `logger.warn`
- `captureException`

The async-aware detections are intentionally narrow and currently recognize:

- same-file async function declarations and async function bindings
- `fetch`
- `Promise.all`, `Promise.allSettled`, `Promise.any`, and `Promise.race`
- axios-style request calls
- timeout-bearing config via `signal` for `fetch` and `timeout` for axios-style calls
- retry wrapper calls such as `retry(...)` or `pRetry(...)`

Current data-flow heuristics are intentionally narrow:

- tracks local identifier aliases created by simple declarations and assignments
- recognizes request-like roots such as `req`, `request`, `event`, `context`,
  `ctx`, `window`, and `location`
- recognizes request/input path segments such as `body`, `query`, `params`,
  `headers`, `cookies`, `payload`, and `session`
- treats common optional-returning methods such as `find`, `get`, and `match`
  as maybe-missing producers
- recognizes validator or sanitizer callees matching `assert*`, `check*`,
  `sanitize*`, `validate*`, and `verify*`
- recognizes risky token/session use through common callee shapes such as
  `decode`, `parseJwt`, `getSession`, and `loadSession`
- recognizes deserializers such as `JSON.parse`, `yaml.load`,
  `yaml.safeLoad`, `jsyaml.load`, `qs.parse`, and `deserialize`

Current structural thresholds and heuristics are intentionally narrow:

- large function: at least 18 statements or cyclomatic complexity 10
- deep nesting: nesting depth 4
- nested loops: loop nesting depth 2
- large payloads: suggestive large-file reads and response `arrayBuffer()` reads
- hardcoded config: top-level config-like names bound to literals

## Repository-Level Augmentation

The adapter focuses on per-file analysis. When `critiq check` runs through
`@critiq/check-runner`, the runtime adds a limited repo pass on top of adapter
output for:

- missing authorization before sensitive backend actions
- missing ownership validation on request-derived ids
- frontend-only authorization mismatches against literal backend routes
- repeated IO in loops and missing batching opportunities
- duplicated large function bodies across files
- direct local import cycles
- missing tests for critical logic
- diff-only logic changes without matching test updates

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
- cross-file analysis inside the adapter itself
- code fixes

Allowed dependencies: `type:core`, `type:util`
