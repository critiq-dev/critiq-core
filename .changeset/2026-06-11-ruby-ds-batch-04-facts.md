---
'@critiq/cli': minor
---

Ruby adapter: add duplicate-constant-assignment, io-select-single-arg, bad-operand-order fact collectors

New `ruby.bug-risk.*` fact collectors in `@critiq/adapter-shared`:
- `ruby.bug-risk.duplicate-constant-assignment` — detects repeated constant assignments per file
- `ruby.bug-risk.io-select-single-arg` — detects IO.select with single IO argument
- `ruby.bug-risk.bad-operand-order` — detects literal-on-left binary expressions (Yoda conditions)
