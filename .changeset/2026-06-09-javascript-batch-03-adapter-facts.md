---
"@critiq/core-adapters": minor
---

Add batch-03 JavaScript parity adapter facts:

- `language.invalid-shebang` (JS-0271) — flags shebang `#!` not on line 1 col 0
- `language.deprecated-api` (JS-0272) — flags known deprecated API usage (`new Buffer()`, `url.parse()`, `domain.create()`, deprecated React lifecycle methods)
- `language.invalid-async-await` (JS-0294) — flags `await`/`for await...of` outside async function
- `language.ts-suppress-directive` (JS-0295) — flags `@ts-ignore`/`@ts-nocheck`/`@ts-expect-error` directives
- `runtime.process-exit-control-flow` (JS-0270) — flags `process.exit()` in finally blocks or with reachable code after
- `quality.banned-type` (JS-0296) — flags `any` type usage
