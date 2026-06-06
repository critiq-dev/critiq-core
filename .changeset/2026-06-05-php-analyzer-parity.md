---
"@critiq/adapter-php": minor
"@critiq/adapter-shared": minor
---

Add 26 PHP analyzer parity adapter facts across correctness, baseline security, and performance: empty array/bracket access, deprecated unset cast and libxml entity loader, duplicate declarations, nested functions and switches, break/continue outside loops, abstract methods outside abstract classes, useless unset/post-increment, invalid regex and cookie options, TODO/FIXME markers, self-assignment, default-parameter ordering, empty function bodies and code blocks, unknown magic methods, case-insensitive define, deprecated filter constants, redundant string cast concat, missing member visibility, function comparison, and unsafe `new static`. Fix PHP-native performance detection for expensive loop conditions (replacing generic polyglot heuristics where PHP-specific analysis applies).
