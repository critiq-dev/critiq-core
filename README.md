# Critiq Core

![banner](./docs/assets/banner.png)

Critiq Core is a standalone open-source toolkit for building repository-level
rules and validations that increase confidence in a pull request review or a
full repository scan.

If you are a developer who wants to:

- run Critiq rules against repository code or a PR diff
- write custom rules for your own codebase
- validate and explain those rules locally
- test rules against fixtures before adopting them
- run deterministic checks in automation before merging code
- run the same checks manually when investigating a change
- publish or share a rule pack with other teams
- build your own tooling on top of stable rule and finding contracts

this repository is the foundation.

`critiq.dev` uses this core, but this repo is not only for `critiq.dev`. It is
intended to be useful on its own.

## What You Can Build With It

This repository gives you the pieces to build a full local rule workflow:

1. Write a rule in the public DSL.
2. Load it from YAML with source-aware diagnostics.
3. Validate the rule contract and its semantics.
4. Normalize it into deterministic internal IR.
5. Run it against analyzed source files.
6. Emit canonical findings.
7. Test the rule against fixtures through `RuleSpec`.

That makes it useful both as:

- a developer tool you can use directly
- a library set you can embed into your own validation or policy system
- a CI-friendly review layer that can increase confidence in PRs before merge
- a repeatable full-scan workflow for checking an entire repository

The core design goal is straightforward:

- no black-box rule execution
- clear findings with evidence and confidence
- deterministic behavior suitable for local use and automation

## How To Organize Rules In Your Own Repo

Critiq does not force one repository layout, but the consumer runtime is now
catalog-first.

A practical consumer setup is:

```text
.critiq/
  config.yaml
```

with:

```yaml
apiVersion: critiq.dev/v1alpha1
kind: CritiqConfig
catalog:
  package: "@critiq/rules"
preset: recommended
disableRules: []
disableCategories: []
disableLanguages: []
ignorePaths: []
severityOverrides: {}
```

If you are authoring local rules as well, a practical convention is:

```text
.critiq/
  config.yaml
  rules/
    no-console.rule.yaml
    no-console.spec.yaml
  fixtures/
    no-console/
      valid.ts
      invalid.ts
```

That convention is recommended because it keeps Critiq content clearly separate
from application code, but it is not required. `critiq check` reads
`.critiq/config.yaml`, while `critiq rules validate|test|normalize|explain`
still accept explicit file paths and globs.

## Start Here

If you are new, use this order:

1. Read this README.
2. Read [docs/guides/getting-started.md](./docs/guides/getting-started.md).
3. Run the starter workflow below.
4. Read [docs/guides/write-your-first-rule.md](./docs/guides/write-your-first-rule.md).
5. Read [CONTRIBUTING.md](./CONTRIBUTING.md) if you want to modify the core.

## Quick Start

### Prerequisites

- Node.js 20 or newer
- npm 10 or newer

### Install

```bash
npm install
```

### Verify The Workspace

```bash
npm run verify
```

### Build The CLI

```bash
npm run nx -- run cli:prune
```

Use `cli:prune` when you want to run the packaged CLI from `dist/`. It builds
the CLI and copies the workspace modules it needs into `dist/apps/cli`.

### Run The Default OSS Catalog

Run the default public catalog against this repository:

```bash
npm run nx -- run cli:prune
mkdir -p .critiq
cat > .critiq/config.yaml <<'EOF'
apiVersion: critiq.dev/v1alpha1
kind: CritiqConfig
catalog:
  package: "@critiq/rules"
preset: recommended
EOF
node dist/apps/cli/main.js check .
```

To explore the maintained OSS rule catalog and starter pack, use the separate
`critiq-rules` repository. With the sibling layout from the split-repo plan,
you can run:

```bash
npm run nx -- run cli:prune
node dist/apps/cli/main.js rules validate "../critiq-rules/examples/starter-pack/rules/*.rule.yaml"
```

Explain one rule:

```bash
npm run nx -- run cli:prune
node dist/apps/cli/main.js rules explain ../critiq-rules/examples/starter-pack/rules/ts.logging.no-console-log.rule.yaml
```

Run the fixture-based specs:

```bash
npm run nx -- run cli:prune
node dist/apps/cli/main.js rules test "../critiq-rules/examples/starter-pack/rules/*.spec.yaml"
```

Run the configured catalog against repository code:

```bash
npm run nx -- run cli:prune
node dist/apps/cli/main.js check .
```

## Using It In Your Own Repository

Create `.critiq/config.yaml`:

```yaml
apiVersion: critiq.dev/v1alpha1
kind: CritiqConfig
catalog:
  package: "@critiq/rules"
preset: recommended
```

Then run the configured catalog against your repository:

```bash
npm run nx -- run cli:prune
node dist/apps/cli/main.js check .
```

If you author local rules as well, assume your repository uses the `.critiq/`
convention.

Validate all local rules:

```bash
npm run nx -- run cli:prune
node dist/apps/cli/main.js rules validate ".critiq/rules/*.rule.yaml"
```

Explain one rule while authoring it:

```bash
npm run nx -- run cli:prune
node dist/apps/cli/main.js rules explain .critiq/rules/no-console.rule.yaml
```

Run all local specs:

```bash
npm run nx -- run cli:prune
node dist/apps/cli/main.js rules test ".critiq/rules/*.spec.yaml"
```

Run the configured catalog against your repository:

```bash
npm run nx -- run cli:prune
node dist/apps/cli/main.js check .
```

Migration:

```bash
# old
node dist/apps/cli/main.js check ".critiq/rules/*.rule.yaml" .

# new
node dist/apps/cli/main.js check .
```

You can replace `.critiq/rules/` with any folder structure you prefer for
authoring commands. The runtime config source of truth remains
`.critiq/config.yaml`.

## Manual And Automated Use

Critiq Core is meant to work in both modes:

- **Manual invocation**
  A developer runs `validate`, `explain`, or `test` while authoring or debugging
  a rule.
- **Automated workflows**
  CI runs Critiq over a rule pack to increase confidence in a PR or over a
  larger ruleset as part of a full repository scan.

The important point is that both modes use the same contracts, the same CLI
surface, and the same deterministic engine.

## Where To Start Depending On Your Goal

### I want to write my own rules

Start here:

1. [docs/guides/write-your-first-rule.md](./docs/guides/write-your-first-rule.md)
2. [docs/reference/rule-dsl-v0alpha1.md](./docs/reference/rule-dsl-v0alpha1.md)
3. [docs/reference/rule-spec.md](./docs/reference/rule-spec.md)
4. clone the separate `critiq-rules` repo if you want the maintained OSS starter pack

### I want to use the CLI in my own workflow

Start here:

1. [apps/cli/README.md](./apps/cli/README.md)
2. [docs/reference/cli.md](./docs/reference/cli.md)

You can also call the reusable workflow in this repository:

```yaml
jobs:
  critiq:
    uses: critiq-dev/critiq-core/.github/workflows/run-critiq-cli.yml@ref
    with:
      critiq-version: x.y.z
      run-check: true
      check-target: .
      validate-glob: .critiq/rules/*.rule.yaml
      test-glob: .critiq/rules/*.spec.yaml
```

Pin both the workflow ref and `critiq-version` in production workflows.

### I want to build my own adapter or runtime integration

Start here:

1. [docs/architecture/repo-map.md](./docs/architecture/repo-map.md)
2. [docs/reference/observation-model.md](./docs/reference/observation-model.md)
3. [docs/reference/predicate-engine-v0.md](./docs/reference/predicate-engine-v0.md)
4. [libs/adapters/typescript](./libs/adapters/typescript)

### I want to understand how this relates to `critiq.dev`

Read [docs/architecture/ecosystem.md](./docs/architecture/ecosystem.md).

The short version:

- this repo is the open core
- `critiq.dev` is one product that composes it
- you can still use this repo independently

## What Outcomes It Is Optimized For

Critiq Core is optimized for developers and teams that want:

- higher confidence in code changes before merge
- less noisy rule execution than ad hoc scripting
- transparent findings backed by evidence
- rule packs that can be reviewed, versioned, and tested like code
- one workflow that works both locally and in CI

## Repository Layout

### CLI

- `apps/cli`
  Local developer workflow for `validate`, `test`, `normalize`, and `explain`.

### Core Packages

- `libs/runtime/check-runner`
  Programmatic `check` workflow, catalog resolution, adapter dispatch, and JSON envelope assembly.
- `libs/core/finding-schema`
  Canonical finding contract and JSON Schema artifact.
- `libs/core/config`
  `.critiq/config.yaml` loading and normalization.
- `libs/core/catalog`
  Rule catalog loading, preset selection, and repository-language filtering.
- `libs/core/rules-dsl`
  Rule DSL contract, YAML loading, validation, and explain helpers.
- `libs/core/diagnostics`
  Source spans, JSON pointers, diagnostics, and formatting.
- `libs/core/ir`
  Stable normalized rule representation and hashing.
- `libs/core/rules-engine`
  Observation model, applicability, evaluation, template rendering, and finding construction.

### Adapter

- `libs/adapters/typescript`
  Example ESTree-backed adapter for `.ts`, `.tsx`, `.js`, and `.jsx`.

### Test Tooling

- `tools/testing/harness`
  `RuleSpec` schema, loader, runner, and reporters.

The maintained OSS catalog and starter pack now live in the separate
`critiq-rules` repository.

## Typical Commands

Workspace-wide:

- `npm run lint`
- `npm run test`
- `npm run build`
- `npm run typecheck`
- `npm run verify`

Release-oriented checks:

- `npm run check:schema-drift`
- `npm run check:package-exports`
- `npm run check:package-contents`
- `npm run release:dry-run`

Useful package targets:

- `npm run nx -- test cli`
- `npm run nx -- test check-runner`
- `npm run nx -- test harness`
- `npm run nx -- test rules-dsl`
- `npm run nx -- test rules-engine`

## What This Repo Does Not Try To Be

This repository is not trying to be:

- a hosted SaaS product
- a code-fix engine
- a type-checking framework
- a cross-repository dependency graph product
- a package manager for rule packs

It is the deterministic open-source rules core that those kinds of systems can
build on top of.

## Compatibility And Releases

The public surfaces are still pre-1.0, but they are documented and tested.

Read:

- [docs/reference/versioning-policy.md](./docs/reference/versioning-policy.md)
- [docs/reference/release-process.md](./docs/reference/release-process.md)
