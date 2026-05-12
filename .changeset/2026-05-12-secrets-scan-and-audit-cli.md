---
"@critiq/cli": minor
---

Add `critiq audit secrets` and a parent `critiq audit --help` command. Extend `critiq check --format json` with an additive `secretsScan` field on the envelope. `critiq check` now runs an advisory secret scan (does not affect check exit code).
