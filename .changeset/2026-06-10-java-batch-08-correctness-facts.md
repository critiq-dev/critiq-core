---
'@critiq/adapter-shared': patch
'@critiq/adapter-java': patch
---

Add 8 Java correctness fact collectors for Batch 08 (JAVA-E family)

Adds fact collectors for:
- equals-inherits-parent (JAVA-E0099)
- equals-null-check (JAVA-E0110)
- compareto-min-value (JAVA-E0112)
- servlet-mutable-fields (JAVA-E0128)
- runnable-run-direct (JAVA-E0135)
- two-lock-wait (JAVA-E0139)
- sync-boxed-primitive (JAVA-E0150)
- class-name-collision (JAVA-E0169)
