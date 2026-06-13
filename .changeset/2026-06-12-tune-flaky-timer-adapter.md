---
'@critiq/typescript-adapter': minor
---

feat: tune testing.flaky-timer-in-test fact for precision

- Removes `Date.now` and `performance.now` from wall-clock callee detection (these are performance measurement clocks, not flaky timers)
- Adds micro-delay threshold: only emits flaky-timer fact for `setTimeout`/`setInterval` with delay argument > 50ms
- No delay argument or numeric literal delay <= 50ms is treated as a micro-delay (event loop yielding) and skipped
- Non-literal delay arguments (variables, expressions) are still flagged since the actual delay value is unknown
