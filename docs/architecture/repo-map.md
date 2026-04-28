# Repository Map

This document explains where changes belong in the `critiq-core` workspace.

Read it after:

1. [../../README.md](../../README.md)
2. [../guides/getting-started.md](../guides/getting-started.md)
3. [./ecosystem.md](./ecosystem.md)

Use it when you need to answer:

- where a change belongs
- which package owns a public contract
- whether a behavior belongs in the CLI, runtime, or an adapter

## Workspace Map

| Path | Import Path | Responsibility |
| --- | --- | --- |
| `apps/cli` | `critiq` | Published CLI package and composition root for `check`, `rules validate`, `rules test`, `rules normalize`, and `rules explain`. |
| `libs/runtime/check-runner` | `@critiq/check-runner` | Reusable repository-scan runtime behind `critiq check`, including config loading, catalog resolution, scope discovery, adapter dispatch, and report assembly. |
| `libs/core/config` | `@critiq/core-config` | `.critiq/config.yaml` contract, normalization, and config loading. |
| `libs/core/catalog` | `@critiq/core-catalog` | Catalog manifests, catalog package resolution, preset filtering, and repository-language detection. |
| `libs/core/diagnostics` | `@critiq/core-diagnostics` | Diagnostic contracts, source spans, and terminal formatting helpers. |
| `libs/core/finding-schema` | `@critiq/core-finding-schema` | Canonical finding schema, validators, and JSON Schema artifacts. |
| `libs/core/rules-dsl` | `@critiq/core-rules-dsl` | Public rule DSL contract, YAML loading, contract validation, semantic validation, and explain helpers. |
| `libs/core/ir` | `@critiq/core-ir` | Canonical normalized rule IR, normalization, and rule hashing. |
| `libs/core/rules-engine` | `@critiq/core-rules-engine` | Deterministic evaluation, selectors, template rendering, and finding construction. |
| `libs/adapters/typescript` | `@critiq/adapter-typescript` | Reference adapter for `.ts`, `.tsx`, `.js`, and `.jsx`, with the richest current fact surface. |
| `libs/adapters/go` | `@critiq/adapter-go` | Early phase-1 Go adapter. |
| `libs/adapters/java` | `@critiq/adapter-java` | Early phase-1 Java adapter. |
| `libs/adapters/php` | `@critiq/adapter-php` | Early phase-1 PHP adapter. |
| `libs/adapters/python` | `@critiq/adapter-python` | Early phase-1 Python adapter. |
| `libs/adapters/ruby` | `@critiq/adapter-ruby` | Early phase-1 Ruby adapter. |
| `libs/adapters/rust` | `@critiq/adapter-rust` | Early phase-1 Rust adapter. |
| `libs/adapters/shared` | `@critiq/adapter-shared` | Shared polyglot helpers used by the non-TypeScript adapters. |
| `libs/utils/file-system` | `@critiq/util-file-system` | Shared file-system helpers. |
| `libs/utils/yaml-loader` | `@critiq/util-yaml-loader` | Shared YAML parsing and pointer-based source mapping utilities. |
| `tools/testing/harness` | `@critiq/testing-harness` | Fixture-backed `RuleSpec` execution, reporters, and authoring assertions. |

## Change Placement Guide

- CLI wording, flags, and terminal UX belong in `apps/cli`.
- Repository scan behavior belongs in `libs/runtime/check-runner`.
- Rule authoring contract changes belong in `libs/core/rules-dsl`.
- Normalization and canonical hashing changes belong in `libs/core/ir`.
- Finding shape changes belong in `libs/core/finding-schema`.
- Language-specific facts belong in the relevant adapter package.
- Shared polyglot parsing or fact helpers belong in `libs/adapters/shared`.
- Fixture execution and author ergonomics belong in `tools/testing/harness`.

## Boundary Rules

- `type:util` may depend only on `type:util`.
- `type:core` may depend on `type:core` and `type:util`.
- `type:adapter` may depend on `type:core` and `type:util`.
- `type:runtime` may depend on `type:core`, `type:adapter`, and `type:util`.
- `type:test` may depend on `type:core`, `type:adapter`, `type:runtime`, and
  `type:util`.
- `type:app` may depend on `type:core`, `type:adapter`, `type:runtime`,
  `type:util`, and `type:test`.
- no project may depend on `type:app`

## Adjacent Repositories

- `critiq-rules`
  The maintained OSS catalog and starter examples consumed by `critiq check`.
- hosted Critiq product and future Pro layers
  Built on the same core contracts, but intentionally outside this workspace.
