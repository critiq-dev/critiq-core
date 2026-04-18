# @critiq/check-runner

`@critiq/check-runner` is the reusable repository-scan runtime behind
`critiq check`.

It owns:

- Critiq config loading
- catalog package resolution
- rule normalization for catalog content
- repository and diff file discovery
- source adapter registration and dispatch
- finding aggregation and deduplication
- the stable `check` JSON envelope

The CLI should remain a thin wrapper over this package.
