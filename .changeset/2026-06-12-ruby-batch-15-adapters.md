---
"@critiq/adapter-shared": minor
"@critiq/adapter-ruby": minor
---

feat(ruby): add 8 RB-RL bug-risk collectors for batch 15

Adds adapters for RB-RL1034-RB-RL1042:
- RB-RL1034: non-null-column-without-default
- RB-RL1035: console-output-instead-of-logger
- RB-RL1037: incorrect-pluralization
- RB-RL1038: use-presence-over-explicit-check
- RB-RL1039: use-present-to-simplify-conditional
- RB-RL1040: rake-task-missing-environment
- RB-RL1041: use-square-brackets-for-attributes
- RB-RL1042: redundant-allow-nil

Also adds .rake to supported Ruby adapter extensions.
