# @critiq/check-runner

`@critiq/check-runner` is the reusable repository-scan runtime behind
`critiq check`.

It owns:

- Critiq config loading
- catalog package resolution
- rule normalization for catalog content
- repository and diff file discovery
- source adapter registration and dispatch
- repo-level heuristic augmentation layered on analyzed files for
  auth/ownership coverage, route mismatches, looped IO, batching, duplication,
  direct import cycles, and test coverage gaps
- finding aggregation and deduplication
- the stable `check` JSON envelope

The CLI should remain a thin wrapper over this package.

See [PROJECT_ANALYSIS.md](./PROJECT_ANALYSIS.md) for the invariants around
project-analysis ranges, normalization, duplicate detection, and source/test
correlation.
