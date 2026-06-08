---
"@critiq/adapter-shared": minor
---

Add Java correctness adapter facts for batch 17 (E1099, E1102, E1104–E1107): invalid time constants, comparator downcast sign flip, CacheLoader null return, incorrect main signature, enum getClass, deprecated Thread methods.

(2 deferred: E1100 nullability — requires cross-file type analysis; E1103 Closeable @Provides — requires type resolution).
