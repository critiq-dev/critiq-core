---
'@critiq/adapter-shared': patch
'@critiq/adapter-java': patch
---

Add 5 Java performance fact collectors for Batch 06 (JAVA-P family)

Adds fact collectors for:
- pattern-compile-in-loop (JAVA-P0331)
- non-zero-to-array (JAVA-P0335)
- keyset-instead-of-entryset (JAVA-P0361)
- replaceall-instead-of-replace (JAVA-P1001)
- single-char-string-indexof (JAVA-P1004)
