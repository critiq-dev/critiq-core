# Critiq Core

![banner](./docs/assets/banner.png)

## Description

Critiq Core is the open source confidence layer behind Critiq.

We built it for developers shipping AI-assisted code who want deterministic,
inspectable review instead of another black-box approval bot. If you are
vibing your way toward production, this repository gives you the public rule,
finding, config, and CLI contracts you can read, adapt, test, and run in CI.

Critiq Core is meant to be useful on its own:

- run a maintained rule catalog against a repository or a diff
- author and test your own rules with fixture-backed `RuleSpec` files
- publish an internal rule pack with stable contracts
- embed Critiq packages inside your own tooling or automation
- keep the same findings and diagnostics locally and in CI

What the OSS core ships today:

- catalog-first `critiq check` for repository and diff-scoped scans
- deterministic rule validation, normalization, and execution
- canonical findings with evidence, provenance, and confidence
- repo-level heuristics layered on top of file analysis
- a reusable GitHub Actions workflow for CI adoption
- first-class TypeScript and JavaScript analysis plus early polyglot adapters

`critiq.dev` and the future Pro layer build on these same contracts, but this
repository is public by design because confidence should not depend on hidden
runtime behavior.

## Repository Layout

### Apps

- `apps/cli`
  The published `critiq` CLI for `check`, `rules validate`, `rules test`,
  `rules normalize`, and `rules explain`.

### Libs

- `libs/core/config`
  Owns `.critiq/config.yaml`, normalization, and config loading.
- `libs/core/catalog`
  Owns rule catalog manifests, package resolution, preset filtering, and
  repository-language detection.
- `libs/core/diagnostics`
  Shared diagnostics, source spans, and terminal formatting contracts.
- `libs/core/finding-schema`
  Defines the canonical finding contract and checked-in JSON Schema artifacts.
- `libs/core/rules-dsl`
  Defines the public rule DSL, YAML loading, contract validation, and semantic
  validation.
- `libs/core/ir`
  Normalizes valid rules into canonical IR and deterministic rule hashes.
- `libs/core/rules-engine`
  Evaluates normalized rules against analyzed files and builds findings.
- `libs/runtime/check-runner`
  Reusable runtime behind `critiq check`, including catalog loading, file
  discovery, diff scoping, and report assembly.
- `libs/adapters/typescript`
  Reference adapter for `.ts`, `.tsx`, `.js`, and `.jsx`.
- `libs/adapters/go`, `libs/adapters/java`, `libs/adapters/php`,
  `libs/adapters/python`, `libs/adapters/ruby`, `libs/adapters/rust`
  Early phase-1 polyglot adapters with narrower coverage than the TypeScript
  adapter.
- `libs/adapters/shared`
  Shared polyglot helpers used by the non-TypeScript adapters.
- `libs/utils/file-system`, `libs/utils/yaml-loader`
  Shared file-system and YAML utilities used across the workspace.

### Tools

- `tools/testing/harness`
  Fixture-backed `RuleSpec` runner and reporters for end-to-end rule tests.

### Adjacent Repositories

- `critiq-rules`
  The maintained OSS rule catalog and starter examples that `critiq check`
  consumes by default.

## Getting Started

### Prerequisites

- Node.js 20 or newer
- npm 10 or newer

### Install And Verify

```bash
npm install
npm run verify
```

### Build The Packaged CLI

```bash
npm run nx -- run cli:prune
```

Use `cli:prune` when you want the packaged runtime in `dist/`. The built
entrypoint is:

```bash
node dist/apps/cli/main.js
```

### Commit A Runtime Config

`critiq check` can fall back to the default OSS catalog and the
`recommended` preset, but we recommend committing `.critiq/config.yaml` so the
confidence policy is explicit in the repository:

```bash
mkdir -p .critiq
cat > .critiq/config.yaml <<'EOF'
apiVersion: critiq.dev/v1alpha1
kind: CritiqConfig
catalog:
  package: "@critiq/rules"
preset: recommended
disableRules: []
disableCategories: []
disableLanguages: []
includeTests: false
ignorePaths: []
severityOverrides: {}
EOF
```

### Run A Repository Check

```bash
node dist/apps/cli/main.js check .
```

### Run A Diff-Scoped Check

```bash
node dist/apps/cli/main.js check . --base origin/main --head HEAD
```

### Run The Rule Authoring Loop

Validate authored rules:

```bash
node dist/apps/cli/main.js rules validate ".critiq/rules/*.rule.yaml"
```

Explain one rule:

```bash
node dist/apps/cli/main.js rules explain .critiq/rules/no-console.rule.yaml
```

Run fixture-backed specs:

```bash
node dist/apps/cli/main.js rules test ".critiq/rules/*.spec.yaml"
```

If you cloned the sibling `critiq-rules` repository, point the same commands at
its example packs instead of local `.critiq/rules/` files.

## Current Coverage

- TypeScript and JavaScript are the deepest supported languages today and power
  the richest adapter-level detections.
- Go, Java, PHP, Python, Ruby, and Rust adapters are included for early
  polyglot coverage and currently expose a narrower fact surface.
- `critiq check` auto-detects repository languages, filters rules by preset and
  config, and emits informational diagnostics when nothing remains active.
- Tests are excluded from `check` by default. Set `includeTests: true` when you
  want them included in scan scope.

## CI Adoption

Consumer repositories can call the reusable workflow published from this repo:

```yaml
jobs:
  critiq:
    uses: critiq-dev/critiq-core/.github/workflows/run-critiq-cli.yml@ref
    with:
      critiq-version: x.y.z
      run-check: true
      check-target: .
      check-base: origin/main
      check-head: HEAD
      validate-glob: .critiq/rules/*.rule.yaml
      test-glob: .critiq/rules/*.spec.yaml
```

The workflow installs the requested `critiq` package, runs the selected
commands with JSON output, uploads the result artifacts, and fails the job when
any Critiq command exits non-zero.

Pin both the workflow ref and `critiq-version` in production automation.

## Docs Map

- New here: [docs/guides/getting-started.md](./docs/guides/getting-started.md)
- Running the CLI: [docs/reference/cli.md](./docs/reference/cli.md)
- Writing rules: [docs/guides/write-your-first-rule.md](./docs/guides/write-your-first-rule.md)
- Repo boundaries: [docs/architecture/ecosystem.md](./docs/architecture/ecosystem.md)
- Package ownership: [docs/architecture/repo-map.md](./docs/architecture/repo-map.md)
- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md)

## OSS Core And Pro

Critiq Core is the open source part of our confidence story. It gives you the
deterministic engine, stable contracts, and local or CI workflow you can adapt
to your own repositories today.

The hosted Critiq product and future Pro offerings build further up the stack:
orchestration, collaboration, policy governance, broader pipeline visibility,
and stronger organizational confidence around what is moving toward production.
The line matters to us. We want the confidence engine itself to remain public,
inspectable, and portable.
