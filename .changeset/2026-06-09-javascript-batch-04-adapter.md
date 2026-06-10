---
'@critiq/adapter-typescript': minor
---

Add batch 04 adapter facts for JavaScript parity (JS-0359, JS-0360, JS-0363, JS-0365, JS-0368, JS-0386)

- JS-0359: `language.require-outside-import` — flags require() calls outside import = require()
- JS-0360: `typescript.prefer-as-const-over-literal-type` — flags literal type annotations where as const would work
- JS-0363: `language.prefer-includes-over-indexof` — flags indexOf comparisons that could use includes()
- JS-0365: `language.prefer-nullish-coalescing` — flags || on identifier with default value
- JS-0368: `typescript.private-member-should-be-readonly` — flags private members that are never mutated
- JS-0386: `typescript.missing-type-annotation` — flags implicit any on parameters and null-initialized variables
