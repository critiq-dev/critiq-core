---
"@critiq/adapter-java": patch
"@critiq/adapter-shared": patch
---

Add 7 new Java correctness fact collectors for batch 11: shift-out-of-range (E0399), oddness-check-fails-negative (E0405), hasnext-invokes-next (E0409), thread-sleep-with-lock (E0410), string-format-arg-mismatch (E1001), bad-short-circuit-null-check (E1003), and wait-notify-on-thread (E1004).
