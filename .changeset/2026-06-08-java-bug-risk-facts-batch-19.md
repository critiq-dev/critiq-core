---
'@critiq/adapter-java': patch
---

Add Java bug risk fact collectors for batch 19 (JAVA-E). Emits 8 new
fact kinds in `java-correctness.ts`: possible-null-access,
possible-null-access-exception, invalidated-iterator, mutable-data-exposed,
duration-with-nanos-misuse, indexof-reversed-arguments, ncopies-argument-order,
class-isinstance-on-class.
