---
"@critiq/cli": patch
---

Extend the TypeScript adapter public security collectors with stronger Node.js framework hardening signals, including Express default-session and cookie sameSite posture, Express parser suppression in explicit dev-only branches, Fastify public listen posture without `trustProxy`, Fastify route-level excessive `bodyLimit` checks, Apollo Server dev tooling plugin exposure heuristics, internal-only suppression for Apollo missing-query-limit posture, GraphQL multipart upload posture when Apollo CSRF is explicitly disabled, NestJS sensitive-route SkipThrottle compensating-control suppression, Nuxt `runtimeConfig.public` secret-shaped keys, and Astro `vite.define` wiring of secret-like `process.env` values into `import.meta.env.PUBLIC_*` keys.
