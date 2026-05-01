<p align="center">
  <img src="https://raw.githubusercontent.com/critiq-dev/critiq-core/main/docs/assets/owl.png" alt="critiq.dev" style="max-height:200px" />
</p>

<h1 align="center">Critiq OSS Core</h1>
<p align="center">
  <strong>Open source static code analysis contracts, rule runtime, and CLI for deterministic code review.<br/>Confident code, not just vibes.</strong>
</p>
<p align="center">
  <a href="https://www.npmjs.com/package/@critiq/cli"><img src="https://img.shields.io/npm/v/%40critiq%2Fcli" alt="npm version" /></a>
  <a href="https://github.com/critiq-dev/critiq-core/actions/workflows/ci.yml"><img src="https://github.com/critiq-dev/critiq-core/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status" /></a>
  <a href="https://github.com/critiq-dev/critiq-core/blob/main/LICENSE"><img src="https://img.shields.io/github/license/critiq-dev/critiq-core" alt="License" /></a>
</p>

<p align="center">
  <img
    src="https://raw.githubusercontent.com/critiq-dev/critiq-core/main/docs/assets/languages.png"
    alt="TypeScript, JavaScript, Node.js, Go, Java, Python, PHP, Ruby, and Rust support"
  />
</p>

<p align="center">
  <code>critiq-core</code> builds and ships <code>@critiq/cli</code>. The workspace keeps the scanner runtime, adapters, and contracts together in one repository, but only the CLI package is published publicly from this repo.
</p>

## Start In 60 Seconds

Run Critiq on your repo:

```bash
npm install -D @critiq/cli @critiq/rules
npx critiq check .
```

Run Critiq against a diff:

```bash
npx critiq check . --base origin/main --head HEAD
```

The npm package surface we are standardizing on is:

- `@critiq/cli` for the CLI and bundled runtime in this repo
- `@critiq/rules` for the default OSS catalog

The low-level workspace libraries in `libs/`, `tools/`, and the language
adapters are repo-internal implementation details and are not published
publicly from this repository.

When you want explicit repository policy later, add `.critiq/config.yaml`. You do not need it for the first run.

## OSS Rule Catalog

We publish the OSS rule catalog as [`@critiq/rules`](https://github.com/critiq-dev/critiq-rules). 

Today it includes `112` rules across `10` categories, with `recommended`, `strict`, `security`, and `experimental` presets.

| Category | Rules | What it looks after |
| --- | ---: | --- |
| Security | 70 | Injection, auth and session gaps, unsafe transport, sensitive data exposure, unsafe file and HTML handling |
| Correctness | 15 | Async bugs, null access, control-flow mistakes, missing fallbacks, race conditions |
| Performance | 10 | Repeated IO, wasted async sequencing, hot-path loops, large retained objects, render churn |
| Quality | 10 | Error handling gaps, oversized functions, coupling, duplicated logic, and weak test coverage |
| Logging | 2 | Console usage and unsafe logging patterns |
| Config | 1 | Configuration access boundaries |
| Next | 1 | Server and client boundary leaks |
| Random | 1 | Unsafe randomness in core logic |
| React | 1 | Cascaded effect fetch patterns |
| Runtime | 1 | Debug-only statements left in shipped code |

### Rule Methodology

We only add rules when they are worth interrupting a developer for.

- We prioritize findings that change code review outcomes: security flaws, correctness bugs, performance regressions, and maintainability problems with real operational cost.
- We prefer rules that are deterministic, explainable, and backed by fixtures, not vague heuristics with noisy output.
- We avoid low-value rules that are already better enforced by compilers, such as TypeScript `tsconfig`, or a standard linter configuration. A blanket `any` detector is a good example: it creates noise, duplicates existing toolchains, and usually says less than the compiler already can.
- A rule should produce an actionable finding with evidence, not just restate generic style guidance.


## What `critiq-core` Is For

- run deterministic repository or diff-scoped checks with the `critiq` CLI
- author, validate, explain, and fixture-test rules with stable contracts
- reuse the same finding schema, diagnostics, and runtime behavior in your own tooling
- keep local runs and CI runs aligned instead of depending on black-box review behavior

## Developer Guide

### Rule Authoring Loop

Validate authored rules:

```bash
node dist/publish/cli/main.js rules validate ".critiq/rules/*.rule.yaml"
```

Explain one rule:

```bash
node dist/publish/cli/main.js rules explain .critiq/rules/no-console.rule.yaml
```

Run fixture-backed specs:

```bash
node dist/publish/cli/main.js rules test ".critiq/rules/*.spec.yaml"
```

If you cloned the separate `critiq-rules` repository, point the same commands at its rule packs instead of local `.critiq/rules/` files.

<details>
<summary><strong>Repository Layout</strong></summary>

### Apps

- `apps/cli`
  The published `@critiq/cli` package for `check`, `rules validate`, `rules test`, `rules normalize`, and `rules explain`.

### Core libraries

- `libs/core/config`
  Owns `.critiq/config.yaml`, normalization, and config loading.
- `libs/core/catalog`
  Owns rule catalog manifests, package resolution, preset filtering, and repository-language detection.
- `libs/core/diagnostics`
  Shared diagnostics, source spans, and terminal formatting contracts.
- `libs/core/finding-schema`
  Defines the canonical finding contract and checked-in JSON Schema artifacts.
- `libs/core/rules-dsl`
  Defines the public rule DSL, YAML loading, contract validation, and semantic validation.
- `libs/core/ir`
  Normalizes valid rules into canonical IR and deterministic rule hashes.
- `libs/core/rules-engine`
  Evaluates normalized rules against analyzed files and builds findings.
- `libs/runtime/check-runner`
  Reusable runtime behind `critiq check`, including catalog loading, file discovery, diff scoping, and report assembly.

### Adapters

- `libs/adapters/typescript`
  Reference adapter for `.ts`, `.tsx`, `.js`, and `.jsx`.
- `libs/adapters/go`, `libs/adapters/java`, `libs/adapters/php`, `libs/adapters/python`, `libs/adapters/ruby`, `libs/adapters/rust`
  Early phase-1 polyglot adapters with narrower coverage than the TypeScript adapter.
- `libs/adapters/shared`
  Shared polyglot helpers used by the non-TypeScript adapters.

### Tools

- `tools/testing/harness`
  Fixture-backed `RuleSpec` runner and reporters for end-to-end rule tests.

### Adjacent OSS repository

- `critiq-rules`
  The maintained OSS rule catalog and starter examples published as `@critiq/rules`.

</details>

## Docs

- New here: [docs/guides/getting-started.md](./docs/guides/getting-started.md)
- Running the CLI: [docs/reference/cli.md](./docs/reference/cli.md)
- Writing rules: [docs/guides/write-your-first-rule.md](./docs/guides/write-your-first-rule.md)
- Repo boundaries: [docs/architecture/ecosystem.md](./docs/architecture/ecosystem.md)
- Package ownership: [docs/architecture/repo-map.md](./docs/architecture/repo-map.md)
- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md)

## OSS Core And Pro

Critiq Core is the open source confidence engine. The hosted Critiq product and future Pro layer build on these same public contracts, then add orchestration, collaboration, policy governance, and wider pipeline visibility.
