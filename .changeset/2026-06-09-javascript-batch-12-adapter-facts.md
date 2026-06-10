---
"@critiq/adapter-typescript": minor
---

Add 4 TypeScript/JavaScript fact collectors for JavaScript parity batch 12:

- `collectLegacyWaiterFacts` (`testing.legacy-waiter`) — detects deprecated testing-library waiter APIs (`wait()`, `waitForElement()`, `waitForDomChange()`) imported from `@testing-library/*` packages in test files
- `collectGetterSideEffectFacts` (`quality.side-effect-in-getter`) — detects assignment expressions, update expressions, and mutation method calls inside getter method bodies
- `collectComputedMissingDependencyFacts` (`framework.vue.computed-missing-dependency`) — detects Vue Options API computed properties that reference identifiers not tracked by Vue's reactivity system (module-level variables, window properties) without explicit `dependencies` arrays
- `collectRulesOfHooksFacts` (`framework.react.hooks-rule-violation`) — detects React hook calls (`use[A-Z]*`) inside conditional blocks, loops, and non-component/non-hook functions

All facts are gated by appropriate context checks to minimize false positives.
