---
'@critiq/cli': minor
---

Ruby adapter: add deprecated-big-decimal-new, symbol-boolean-name, circular-argument-reference, deprecated-class-methods, disjunctive-assignment-in-constructor fact collectors

New `ruby.bug-risk.*` fact collectors in `@critiq/adapter-shared`:
- `ruby.bug-risk.deprecated-big-decimal-new` — detects deprecated `BigDecimal.new` calls
- `ruby.bug-risk.symbol-boolean-name` — detects `:true` and `:false` symbol literals
- `ruby.bug-risk.circular-argument-reference` — detects method arguments with self-referencing defaults
- `ruby.bug-risk.deprecated-class-methods` — detects deprecated `File.exists?`, `Dir.exists?`, and `iterator?`
- `ruby.bug-risk.disjunctive-assignment-in-constructor` — detects redundant `||=` in `initialize`
