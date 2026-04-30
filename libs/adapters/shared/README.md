# @critiq/adapter-shared

`@critiq/adapter-shared` provides reusable infrastructure for deterministic
adapter analysis in `critiq-core`.

## Public API

The package intentionally exposes shared building blocks rather than a single
adapter entrypoint. The public surface includes:

- regex/polyglot adapter composition via `createRegexPolyglotAdapter(...)`
- analyzed-file and observed-fact assembly helpers
- parser-agnostic scan-state, delimiter, and text helpers
- reusable polyglot fact collectors for shared security domains

## Intended Usage

Use this package when adapter logic is already shared across multiple language
packages or is clearly parser-agnostic.

Keep adapter-specific AST walking, naming vocabularies, and product policy out
of this package.

## Behavior And Limits

- shared helpers are deterministic and file-local
- polyglot collectors operate on text or lightweight scan state
- failures should still be surfaced by the calling adapter as structured
  diagnostics
- this package does not own CLI orchestration, repository traversal, or hosted
  workflows
