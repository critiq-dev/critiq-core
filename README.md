
<p align="center">
    <img src="./docs/assets/owl.png" alt="critiq.dev" style="max-height:200px" />
</p>

<h1 align="center">Critiq OSS Core</h1>
<p align="center">
  <strong>Open source static code analysis contracts, rule runtime, and CLI for deterministic code review. <br/>Confident code, not just vibes</strong>
</p>
<br/>
<p align="center">
    <img
      src="./docs/assets/languages.png"
      alt="TypeScript, JavaScript, Node.js, Go, Java, Python, PHP, Ruby, and Rust support"
    />
</p>
<br/>
<p align="center">
  <code>critiq-core</code> is the public engine behind Critiq. It gives developers a readable rule DSL, canonical finding contracts, a reusable scan runtime, and a CLI that behaves the same way locally and in CI. We support scanning of typescript, javascript, Node.Js, Go, Java, Python, PHP, Ruby, and Rust. 
</p>

<p align="center">
We are constantly adding new rules and improving existing rules. We publish these rules via <code>@critiq/rules</code> on npm. There you will find the following: 
<table>
  <tr>
    <td align="center"><strong>112</strong><br/>OSS rules via <code>@critiq/rules</code></td>
    <td align="center"><strong>10</strong><br/>rule categories</td>
    <td align="center"><strong>4</strong><br/>presets</td>
  </tr>
</table>
</p>

## Start In 60 Seconds

Run Critiq on your repo:

```bash
npm install -D @critiq/critiq @critiq/rules
npx critiq check .
```

Run Critiq against a diff:

```bash
npx critiq check . --base origin/main --head HEAD
```

The npm package surface we are standardizing on is:

- `@critiq/critiq` for the reusable engine and contracts in this repo
- `@critiq/rules` for the default OSS catalog

When you want explicit repository policy later for more advance configurations, create `.critiq/config.yaml`. You do not need it to get started.



## What `critiq-core` Is For

- run deterministic repository or diff-scoped checks with the `critiq` CLI
- author, validate, explain, and fixture-test rules with stable contracts
- reuse the same finding schema, diagnostics, and runtime behavior in your own tooling
- keep local runs and CI runs aligned instead of depending on black-box review behavior

## Developer Guide

### Rule Authoring Loop

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
