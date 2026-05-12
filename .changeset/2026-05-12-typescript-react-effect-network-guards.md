---
"@critiq/cli": patch
---

Extend the TypeScript adapter for `ts.react.no-effect-fetch-without-cancellation` (and related facts): treat GraphQL client-style `.query`/`.mutate` calls and `graphql-request` imports as network sources, honor Apollo-style `context.fetchOptions.signal`, suppress when the enclosing component uses `useLoaderData` / `useRouteLoaderData`, and respect common stale-response guard patterns (`cancelled`/`ignore` flags with cleanup).
