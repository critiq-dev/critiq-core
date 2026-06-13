---
'@critiq/typescript-adapter': minor
---

feat: tune security.iframe-missing-sandbox-attribute fact for precision

- Skips iframes with `allowFullScreen` attribute — signals intentional trust (app marketplace embeds, payment gateways that need full browser capabilities)
- Skips iframes with `allow` attribute — signals explicit CORS/permission policy management
- Plain iframes without `sandbox`, `allowFullScreen`, or `allow` continue to be flagged
