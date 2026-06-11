---
'@critiq/adapter-shared': patch
'@critiq/adapter-java': patch
---

Add 8 Java correctness fact collectors for Batch 09 (JAVA-E family)

Adds fact collectors for:
- ignored-inputstream-read (JAVA-E0183)
- ignored-inputstream-skip (JAVA-E0184)
- constructor-starts-thread (JAVA-E0208)
- for-loop-mismatched-increment (JAVA-E0214)
- readline-without-null-check (JAVA-E0220)
- unsynchronized-wait-notify (JAVA-E0288)
- self-assignment (JAVA-E0291)
- sync-on-lock-primitive (JAVA-E0321)
