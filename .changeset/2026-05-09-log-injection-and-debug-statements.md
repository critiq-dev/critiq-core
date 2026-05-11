---
"@critiq/cli": patch
---

Extend the TypeScript adapter with two new logging/disclosure facts and broaden recognized logger families. New facts `security.log-injection` and `security.debug-statement-in-source` cover request-controlled values flowing into pino, winston, bunyan, or consola messages and leftover `debugger;` / `console.trace()` calls in production paths. Existing `security.sensitive-data-in-logs-and-telemetry` and `security.information-leakage` now also recognize the broader pino/winston/bunyan/consola logger family sinks.
