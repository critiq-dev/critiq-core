# Contributing

This repository is the OSS core of `critiq.dev`. Contributions should make the
open contracts, runtime behavior, and local author workflow clearer and more
deterministic, not less.

## Before You Change Code

Make sure you know which layer you are changing:

- `apps/cli`
  Command composition and local workflow UX
- `libs/core/*`
  Public contracts and runtime behavior
- `libs/runtime/*`
  Runtime composition that stays reusable outside the CLI
- `libs/adapters/*`
  Language-specific source analysis
- `libs/utils/*`
  Reusable utilities with no domain ownership
- `tools/testing/harness`
  RuleSpec and fixture-driven testing

The maintained OSS catalog and starter content now live in the separate
`critiq-rules` repository.

If you are not sure where something belongs, read
[docs/architecture/repo-map.md](./docs/architecture/repo-map.md) first.

If you are changing an adapter, also read
[libs/adapters/Agents.md](./libs/adapters/Agents.md).

## Local Setup

Prerequisites:

- Node.js 20 or newer
- npm 10 or newer

Install:

```bash
npm install
```

Recommended first commands:

```bash
npm run nx -- graph
npm run verify
```

## Typical Contributor Workflows

### Working On Rule Authoring

Use the CLI against local rule files or the separate `critiq-rules` repo:

```bash
npm run build:release-cli
node dist/publish/cli/main.js rules validate ".critiq/rules/*.rule.yaml"
node dist/publish/cli/main.js rules explain .critiq/rules/no-console.rule.yaml
node dist/publish/cli/main.js rules test ".critiq/rules/*.spec.yaml"
```

### Working On Runtime Packages

Run the narrowest useful targets while iterating:

```bash
npm run nx -- test rules-dsl
npm run nx -- test rules-engine
npm run nx -- test harness
npm run nx -- typecheck cli
```

Before considering the work done, run:

```bash
npm run verify
```

### Working On Release-Oriented Changes

If you touch package exports, schema artifacts, or publish behavior, also run:

```bash
npm run release:verify
```

If the change affects shipped CLI behavior, add a changeset:

```bash
npm run changeset
```

## Contribution Rules

### Architectural Boundaries

- `apps/cli` is the only composition root.
- Respect the `type:*` project tags enforced by Nx module boundaries.
- Do not move product-specific hosted behavior into the OSS core.
- Keep parser-specific or adapter-specific logic out of the core packages.
- Keep reusable contracts and deterministic behavior in `libs/core/*`.

### Public Surface Discipline

Changes to any of these need extra care:

- rule DSL contract
- finding schema
- CLI flags or JSON output envelopes
- adapter property-path guarantees
- RuleSpec contract

If a change affects a documented public surface:

1. update tests
2. update the relevant reference doc
3. add or update the corresponding changeset

### OSS Rules Content

The maintained OSS catalog and starter-pack fixtures now live in
`critiq-rules`. Keep `critiq-core` focused on scanner/runtime concerns and make
example-rule changes in the rules repo instead.

## Documentation Expectations

Documentation is part of the change, not follow-up work.

Update docs when you change:

- repository structure
- public package behavior
- CLI behavior
- starter workflows
- compatibility or release guarantees

At minimum, evaluate whether these need updates:

- [README.md](./README.md)
- [docs/architecture/repo-map.md](./docs/architecture/repo-map.md)
- the package README you touched
- the relevant file under `docs/reference/`

## Testing Expectations

Choose the smallest meaningful test surface while iterating, then finish with
the full gate.

Examples:

- package contract change: package tests + package typecheck + full verify
- CLI change: `cli:test` + `cli:typecheck` + full verify
- harness change: `harness:test` + rules-repo `RuleSpec` tests + full verify
- adapter change: adapter tests + rules-engine integration coverage + full verify

Required final gate:

```bash
npm run verify
```

## Release And Compatibility

This repo uses Changesets and explicit docs for compatibility guarantees.

Use `npm run commit` for Commitizen-formatted commit messages when you want the
release notes to classify your change cleanly.

Read these before changing a public surface:

- [docs/reference/versioning-policy.md](./docs/reference/versioning-policy.md)
- [docs/reference/release-process.md](./docs/reference/release-process.md)

## Pull Request Checklist

Before opening or merging work, confirm:

- the code is in the correct package or layer
- tests cover the new behavior
- `npm run verify` passes
- public-surface docs were updated when needed
- release-related checks were run if package/export/schema behavior changed
