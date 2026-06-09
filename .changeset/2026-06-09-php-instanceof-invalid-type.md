---
"@critiq/adapter-shared": patch
"@critiq/adapter-php": patch
---

feat(php): add instanceof-invalid-type fact collector for PHP-E1009 parity

Adds `php.correctness.instanceof-invalid-type` fact kind that detects
`instanceof` with non-class operands (self/parent outside class scope,
PHP keywords, string/number/array literals). Core-only; no rule DSL changes.
