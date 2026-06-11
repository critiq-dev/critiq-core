---
'@critiq/adapter-shared': patch
'@critiq/adapter-java': patch
---

Add 7 Java correctness fact collectors for Batch 06 (JAVA-E family)

Adds fact collectors for:
- volatile-array-elements (JAVA-E0027)
- volatile-increment-non-atomic (JAVA-E0028)
- unsafe-getresource (JAVA-E0029)
- duplicate-binary-argument (JAVA-E0034)
- illegal-monitor-state-caught (JAVA-E0040)
- clone-without-super (JAVA-E0048)
- equals-null (JAVA-E0051)
