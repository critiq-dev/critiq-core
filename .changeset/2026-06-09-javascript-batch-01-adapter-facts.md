---
"@critiq/core-adapters": minor
---

Add batch-01 JavaScript parity adapter facts:

- `language.new-symbol-instance` (JS-0233) — flags `new Symbol()` usage
- `language.var-declaration` (JS-0239) — flags `var` declarations
- `language.parse-int-on-number-literal` (JS-0253) — flags `parseInt`/`Number.parseInt` on number literals
- `language.assignment-to-exports` (JS-0256) — flags `exports = ` reassignment
- `language.callback-missing-error-handling` (JS-0254) — flags callbacks with unused error params
- `language.callback-not-error-first` (JS-0255) — flags callbacks with wrong parameter order
- `language.extraneous-import` (JS-0257) — flags unused import bindings
