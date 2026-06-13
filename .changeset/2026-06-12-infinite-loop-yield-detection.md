---
'@critiq/typescript-adapter': minor
---

**async.infinite-loop fact**: Added YieldExpression detection to loopBodyHasExit

Generator functions using `while(true) { yield value; }` are now correctly
recognized as having an exit path (cooperative suspension via yield). This
reduces false positives for generator-based infinite sequences.
