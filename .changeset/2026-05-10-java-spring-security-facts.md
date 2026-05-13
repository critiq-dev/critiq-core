---
"@critiq/cli": patch
---

Extend the Java adapter with new security fact collectors and Spring Boot support. Adds polyglot domains for insecure servlet cookies, open redirects, response-writer XSS, sensitive data egress, and Spring config debug exposure (`spring-config-debug-exposure`), wired through `@critiq/adapter-java` and shared polyglot analysis.
