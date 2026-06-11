---
'@critiq/adapter-shared': patch
'@critiq/adapter-java': patch
---

Add 5 Java correctness fact collectors for Batch 10 (JAVA-E family)

Adds fact collectors for:
- result-set-index-zero (JAVA-E0343)
- prepared-statement-index-zero (JAVA-E0344)
- impossible-toarray-downcast (JAVA-E0386)
- invalid-regex-literal (JAVA-E0394)
- lost-increment-in-assignment (JAVA-E0396)
