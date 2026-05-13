---
"@critiq/cli": patch
---

Add TypeScript adapter security fact collectors for Angular, NestJS, and Next.js. New custom facts cover Angular DOM sanitizer bypass (`angular-dom-sanitizer`), NestJS hardening (`nestjs-security`: Helmet ordering, global validation pipe, throttling, whitelist), Next.js Server Actions local auth (`next-server-actions`), and shared `node-framework-bootstrap` / `react-next-best-practices` helpers used by these detectors.
