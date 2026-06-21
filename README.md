<p align="center">
  <img src="https://raw.githubusercontent.com/critiq-dev/critiq-core/main/docs/assets/banner-cli.png" alt="critiq.dev" style="max-height:400px" />
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


Think of Critiq as an extra code reviewer that scans your project for bugs, security issues, performance problems, and risky changes before they turn into production incidents. Instead of checking style, it focuses on the kinds of problems that usually slip through review and cause real trouble later. You run it locally or in CI, and it gives you deterministic findings you can act on before merging code.


It does this by parsing your code, matching it against a curated catalog of explicit rules, and reporting findings with concrete evidence tied to the code that triggered them. That means the output is based on repeatable checks for things like unsafe SQL, missing authorization, repeated IO in loops, and untested critical logic changes, not vague heuristics or style-only linting.

<p align="center">
  <img
    src="https://raw.githubusercontent.com/critiq-dev/critiq-core/main/docs/assets/cli-architecture.png"
    alt="Cli Architecture"
  />
</p>

By default, `@critiq/cli` uses the open source [`@critiq/rules`](https://www.npmjs.com/package/@critiq/rules) catalog with recommended rules. You can customize which rules are used either by passing command-line flags or by creating a `.critiq/config.yaml` configuration file.

## Start In 60 Seconds

Run Critiq on your repo:

```bash
npm install -D @critiq/cli @critiq/rules
npx @critiq/cli check .
```

Run Critiq against a diff:

```bash
npx @critiq/cli check . --base origin/main --head HEAD
```

Enable the built-in secret scan alongside rules:

```bash
npx @critiq/cli check . --secrets
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

Today it includes `1023` rules across `10` languages, with `recommended`, `strict`, `security`, and `experimental` presets. Browse the full catalog at [docs.critiq.dev/rules](https://docs.critiq.dev/rules).

| Language | Rules | What it looks after |
| --- | ---: | --- |
| TypeScript | 335 | Security (Express, NestJS, Apollo, Electron, Angular, Vue, Next.js), correctness (async bugs, null access, control-flow), performance, quality, React, testing, logging, config, and runtime |
| CloudFormation | 157 | AWS CloudFormation and SAM template validation (correctness, maintainability, and security) via wrapped cfn-lint |
| Java | 106 | Correctness bugs, performance, Spring/Servlet/JPA/Android security, and testing |
| Rust | 101 | Correctness (transmute safety, async pitfalls, IO handling), quality, performance, security (Actix, Axum, Rocket, SQL), and testing |
| PHP | 104 | Correctness (missing returns, invalid static calls, type errors), performance, security (Laravel, Symfony, WordPress), and testing |
| Go | 95 | Correctness (nil checks, goroutine bugs, defer mistakes), performance, security (Gin, Echo, Fiber), and testing |
| Python | 61 | Correctness, Django/DRF/Flask/FastAPI security, performance, and testing |
| Ruby | 38 | Bug risk, Rails security (CSRF, XSS, strong params), performance, and testing |
| Shared | 13 | Cross-language security rules (hardcoded credentials, SQL injection, path traversal, TLS verification) |
| SQL | 13 | SQL correctness (undefined references) and style (aliases, keyword casing, formatting) |

### Rule Methodology

We only add rules when they are worth interrupting a developer for.

- We prioritize findings that change code review outcomes: security flaws, correctness bugs, performance regressions, and maintainability problems with real operational cost.
- We prefer rules that are deterministic, explainable, and backed by fixtures, not vague heuristics with noisy output.
- We avoid low-value rules that are already better enforced by compilers, such as TypeScript `tsconfig`, or a standard linter configuration. A blanket `any` detector is a good example: it creates noise, duplicates existing toolchains, and usually says less than the compiler already can.
- A rule should produce an actionable finding with evidence, not just restate generic style guidance.

## High-Value Rules In The Default Catalog

| Rule title | Description |
| --- | --- |
| `Hardcoded API keys or credentials` | Source files should not embed credential-like string literals. |
| `Avoid raw or interpolated SQL`| Database query sinks must not receive request-driven or dynamically interpolated SQL text. |
| `Path traversal via user input` | File access calls must not use request-controlled paths directly. |
| `Protect deserialization trust boundaries`| Deserializers should not consume untrusted payloads directly across a trust boundary. |
| `Server-side request forgery` (`ts.security.ssrf`) | Outbound requests should not use attacker-controlled targets or private hosts. |
| `Open redirect via request-controlled target`| Redirect and navigation sinks should not use request-controlled destinations without validation. |
| `Missing authorization before sensitive action` | Sensitive backend actions should be guarded by an authorization or permission check. |
| `Use authenticated encryption for secrets and tokens` | Session, cookie, and token encryption should provide integrity protection in the same helper. |
| `Missing await on async call` | Async functions should not drop direct async calls without awaiting them. |
| `Repeated IO call inside loop` | Database or network calls inside loops can multiply latency and load. |
| `Logic change without corresponding test updates` | Diffs that change critical logic should usually update the matching tests in the same change. |
| `Avoid server/client boundary leaks in Next.js` | Server components should not use browser-only APIs or client-only hooks without an explicit client boundary. |

## What `critiq-core` Is For

- run deterministic repository or diff-scoped checks with the `critiq` CLI
- author, validate, explain, and fixture-test rules with stable contracts
- reuse the same finding schema, diagnostics, and runtime behavior in your own tooling
- keep local runs and CI runs aligned instead of depending on black-box review behavior

## Developer Guide

<p align="left">
  <code>critiq-core</code> builds and ships <code>@critiq/cli</code>. The workspace keeps the scanner runtime, adapters, and contracts together in one repository, but only the CLI package is published publicly from this repo.
</p>

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

- [critiq.dev](https://critiq.dev) — product site
- [docs.critiq.dev](https://docs.critiq.dev) — full documentation
- [Getting started](https://docs.critiq.dev/getting-started)
- [CLI reference](https://docs.critiq.dev/cli)
- [Writing rules](https://docs.critiq.dev/guides/writing-rules)
- [GitHub Actions](https://docs.critiq.dev/ci/github-actions)
- Repo boundaries: [docs/architecture/ecosystem.md](./docs/architecture/ecosystem.md)
- Package ownership: [docs/architecture/repo-map.md](./docs/architecture/repo-map.md)
- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md)

## OSS Core And Pro

Critiq Core is the open source confidence engine. The hosted Critiq product and future Pro layer build on these same public contracts, then add orchestration, collaboration, policy governance, and wider pipeline visibility. Learn more at [critiq.dev](https://critiq.dev).
