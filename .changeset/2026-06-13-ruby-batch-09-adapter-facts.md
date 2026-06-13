---
'@critiq/adapter-shared': minor
'@critiq/cli': minor
---

Ruby batch 09 (RB-RL) adapter facts

- Add 7 new fact kinds: redundant-with-options-receiver, class-name-should-be-string, non-preferred-assert-falseness, relative-date-as-constant, inconsistent-request-referrer, inconsistent-safe-navigation-try, safe-navigation-with-blank
- Extend irreversible-migration collector to detect irreversible operations (drop_table, remove_column, etc.) inside `def change` methods
- Wire all new collectors into collectRubyBugRiskFacts
- Alias codes: RB-RL1043 through RB-RL1050
