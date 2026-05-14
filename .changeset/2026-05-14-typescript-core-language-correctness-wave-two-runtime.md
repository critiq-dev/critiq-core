---
"@critiq/adapter-typescript": minor
---

Add language facts for empty non-function blocks, catch-parameter reassignment, and regexp patterns that embed unusual ASCII control characters, backing three new `ts.correctness.*` catalog rules.

Treat `regex.pattern` as pattern source text: decode common escapes (`\xNN`, `\uNNNN`, `\u{...}`, and `\v`/`\f`/`\b`) so controls such as `\x02` are detected while tab, LF, and CR remain allowed (including via `\t`, `\n`, `\r`, and matching hex escapes).
