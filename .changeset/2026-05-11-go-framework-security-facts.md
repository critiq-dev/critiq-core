---
"@critiq/cli": feat
---

Add Go and framework security fact collectors through the shared polyglot `go-security` domain and `@critiq/adapter-go` wiring. Includes Go open redirect and SSRF facts (reused by existing multi-language rules), Go-specific sensitive egress, tar path traversal, net/http timeout posture, Gin CORS/proxy/binding checks, Echo/Fiber binding and upload checks, template trusted-type misuse, plus broader Go request-source and SQL helper (`Raw`/`RawContext`) coverage.
