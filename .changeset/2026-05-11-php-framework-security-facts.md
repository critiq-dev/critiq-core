---
"@critiq/cli": patch
---

Add PHP framework security fact coverage on top of the existing polyglot baseline by wiring new shared collectors into `@critiq/adapter-php`. The shipped slice includes Laravel mass assignment, sensitive CSRF exclusions, unsafe raw Blade output, Symfony debug/CSRF posture checks, WordPress nonce-capability and unprepared SQL signals, plus session/cookie hardening, wildcard CORS-with-credentials, insecure plaintext transport, unsafe upload handling, and sensitive data egress facts.
