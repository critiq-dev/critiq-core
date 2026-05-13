---
"@critiq/cli": feat
---

Add Java Spring framework security fact collectors (`java-framework-security` in `@critiq/adapter-shared`), wire them from `@critiq/adapter-java`, extend Java scan extensions with Spring Boot `application`/`bootstrap` `*.yml` plus `.html`/`.htm` for template-oriented findings, and stop folding wildcard actuator exposure into `security.spring-debug-exposure` (debug and verbose logging only there).
