# Repository Map

This document records the package map, dependency boundaries, and ownership for
the Critiq Core workspace.

Read this after:

1. [README.md](../../README.md)
2. [Getting Started](../guides/getting-started.md)
3. [Critiq Ecosystem](./ecosystem.md)

Use it when you need to answer:

- where a change belongs
- which package owns a contract
- which dependency directions are allowed

| Path                       | Import Path                    | Purpose                                                             | Allowed Dependencies                                                  | Owner                |
| -------------------------- | ------------------------------ | ------------------------------------------------------------------- | --------------------------------------------------------------------- | -------------------- |
| `apps/cli`                 | n/a                            | CLI composition root for `check`, validate, test, normalize, and explain workflows. | `type:core`, `type:adapter`, `type:runtime`, `type:util`, `type:test` | OSS Core maintainers |
| `libs/runtime/check-runner`| `@critiq/check-runner`        | Programmatic repository scan runtime, adapter registry, and `check` envelope assembly. | `type:core`, `type:adapter`, `type:util`                              | OSS Core maintainers |
| `libs/core/finding-schema` | `@critiq/core-finding-schema`  | Canonical v0 finding contract, validator, and JSON Schema artifact. | `type:core`, `type:util`                                              | OSS Core maintainers |
| `libs/core/config`         | `@critiq/core-config`          | `.critiq/config.yaml` contract, loading, and normalization.         | `type:core`, `type:util`                                              | OSS Core maintainers |
| `libs/core/catalog`        | `@critiq/core-catalog`         | Rule catalog loading, package resolution, preset filtering, and repository-language selection. | `type:core`, `type:util`                                              | OSS Core maintainers |
| `libs/core/rules-dsl`      | `@critiq/core-rules-dsl`       | Public rule DSL contract, validator, JSON Schema, and YAML rule loader API. | `type:core`, `type:util`                                              | OSS Core maintainers |
| `libs/core/diagnostics`    | `@critiq/core-diagnostics`     | Source spans, diagnostic contracts, and deterministic renderers.    | `type:core`, `type:util`                                              | OSS Core maintainers |
| `libs/core/rules-engine`   | `@critiq/core-rules-engine`    | Language-agnostic observation model, selectors, deterministic predicate engine, template rendering, and finding construction. | `type:core`, `type:util`                                              | OSS Core maintainers |
| `libs/core/ir`             | `@critiq/core-ir`              | Canonical normalized rule IR, canonical hashing, and debug/source sidecars. | `type:core`, `type:util`                                              | OSS Core maintainers |
| `libs/adapters/typescript` | `@critiq/adapter-typescript`   | Example ESTree-backed adapter for `.ts`, `.tsx`, `.js`, and `.jsx` source analysis. | `type:core`, `type:util`                                              | OSS Core maintainers |
| `libs/utils/file-system`   | `@critiq/util-file-system`     | Shared file-system helpers used across the workspace.               | `type:util`                                                           | OSS Core maintainers |
| `libs/utils/yaml-loader`   | `@critiq/util-yaml-loader`     | Generic YAML parsing and pointer-based source mapping helpers.      | `type:util`                                                           | OSS Core maintainers |
| `tools/testing/harness`    | `@critiq/testing-harness`      | Fixture-based RuleSpec runner, reporters, and package-level workspace assertions. | `type:core`, `type:adapter`, `type:runtime`, `type:util`              | OSS Core maintainers |

## Boundary Rules

- `type:util` may depend only on `type:util`.
- `type:core` may depend on `type:core` and `type:util`.
- `type:adapter` may depend on `type:core` and `type:util`.
- `type:runtime` may depend on `type:core`, `type:adapter`, and `type:util`.
- `type:test` may depend on `type:core`, `type:adapter`, `type:runtime`, and `type:util`.
- `type:app` may depend on `type:core`, `type:adapter`, `type:runtime`, `type:util`, and `type:test`.
- No project may depend on `type:app`.

The maintained OSS rules catalog and starter-pack content now live in the
separate `critiq-rules` repository.
