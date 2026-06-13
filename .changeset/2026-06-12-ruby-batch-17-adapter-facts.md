---
"@critiq/cli": minor
"@critiq/adapter-shared": minor
"@critiq/adapter-ruby": minor
---

feat(ruby): add batch 17 bug-risk and performance fact collectors (RB-RL1052-RB-RL1059)

Adds 4 new bug-risk fact collectors:
- `ruby.bug-risk.plain-method-instead-of-proc` (RB-RL1052)
- `ruby.bug-risk.time-without-zone` (RB-RL1054)
- `ruby.bug-risk.invalid-rails-env-predicate` (RB-RL1056)
- `ruby.bug-risk.old-style-validation-macro` (RB-RL1057)

Adds 2 new performance fact collectors:
- `ruby.performance.enumerable-index-by` (RB-RL1058)
- `ruby.performance.enumerable-index-with` (RB-RL1059)

RB-RL1051 and RB-RL1055 are deferred (need AST-level analysis).
