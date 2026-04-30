# Critiq Core

![banner](./docs/assets/banner.png)

<p align="center">
  <a href="https://skillicons.dev">
    <img
      src="https://skillicons.dev/icons?i=ts,js,nodejs,go,java,python,php,ruby,rust&perline=9"
      alt="TypeScript, JavaScript, Node.js, Go, Java, Python, PHP, Ruby, and Rust support"
    />
  </a>
</p>

<p align="center">
  <strong>Open source static analysis contracts, rule runtime, and CLI for deterministic code review.</strong>
</p>

<p align="center">
  <code>critiq-core</code> is the public engine behind Critiq. It gives developers a readable rule DSL, canonical finding contracts, a reusable scan runtime, and a CLI that behaves the same way locally and in CI.
</p>

<table>
  <tr>
    <td align="center"><strong>112</strong><br/>OSS rules via <code>@critiq/rules</code></td>
    <td align="center"><strong>10</strong><br/>rule categories</td>
    <td align="center"><strong>4</strong><br/>presets</td>
  </tr>
</table>

## Start In 60 Seconds

> Zero-config first run: `critiq check` falls back to the OSS `@critiq/rules` catalog and the `recommended` preset. You do not need `.critiq/config.yaml` for the first scan.

Run Critiq from this repo today:

```bash
npm install
npm run nx -- run cli:prune
node dist/apps/cli/main.js check .
```

Run against a diff:

```bash
node dist/apps/cli/main.js check . --base origin/main --head HEAD
```

The npm package surface we are standardizing on is:

- `critiq` for repository and diff-scoped scans
- `@critiq/core` for the reusable engine and contracts in this repo
- `@critiq/rules` for the default OSS catalog

Once that package surface is published, the zero-config consumer flow becomes:

```bash
npm install -D critiq @critiq/rules
npx critiq check .
```

When you want explicit repository policy later, commit `.critiq/config.yaml`. You do not need it to get started.

## What `critiq-core` Is For

- run deterministic repository or diff-scoped checks with the `critiq` CLI
- author, validate, explain, and fixture-test rules with stable contracts
- reuse the same finding schema, diagnostics, and runtime behavior in your own tooling
- keep local runs and CI runs aligned instead of depending on black-box review behavior

## OSS Catalog Snapshot

The default OSS catalog in `@critiq/rules` currently covers:

| Category | Rules |
| --- | ---: |
| Security | 70 |
| Correctness | 15 |
| Performance | 10 |
| Quality | 10 |
| Logging | 2 |
| Config | 1 |
| Next | 1 |
| Random | 1 |
| React | 1 |
| Runtime | 1 |

Supported presets: `recommended`, `strict`, `security`, `experimental`

## Rule Authoring Loop

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

If you cloned the separate `critiq-rules` repository, point the same commands at its rule packs instead of local `.critiq/rules/` files.

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
```

Pin both the workflow ref and `critiq-version` in production automation.

<details>
<summary><strong>Repository Layout</strong></summary>

### Apps

- `apps/cli`
  The published `critiq` CLI for `check`, `rules validate`, `rules test`, `rules normalize`, and `rules explain`.

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
