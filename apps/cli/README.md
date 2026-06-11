<p align="center">
  <img src="https://raw.githubusercontent.com/critiq-dev/critiq-core/main/docs/assets/banner-cli.png" alt="critiq.dev" style="max-height:400px" />
</p>

<h1 align="center">Critiq CLI</h1>
<p align="center">
  <strong>Open source deterministic static analysis for code review.<br/>Run high-signal checks on your codebase to identify security, performance, scaling issues before it goes to production</strong>
</p>
<p align="center">
  <a href="https://www.npmjs.com/package/@critiq/cli"><img src="https://img.shields.io/npm/v/%40critiq%2Fcli" alt="npm version" /></a>
  <a href="https://github.com/critiq-dev/critiq-core/tree/main/apps/cli"><img src="https://img.shields.io/badge/source-GitHub-181717?logo=github" alt="Source" /></a>
  <a href="https://github.com/critiq-dev/critiq-core/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License" /></a>
</p>



Think of Critiq as an extra code reviewer that scans your project for bugs, security issues, performance problems, and risky changes before they turn into production incidents. Instead of only checking style, it focuses on the kinds of problems that usually slip through review and cause real trouble later. You run it locally or in CI, and it gives you deterministic findings you can act on before merging code.


It does this by parsing your code, matching it against a curated catalog of explicit rules, and reporting findings with concrete evidence tied to the code that triggered them. That means the output is based on repeatable checks for things like unsafe SQL, missing authorization, repeated IO in loops, and untested critical logic changes, not vague heuristics or style-only linting.

<p align="center">
  <img
    src="https://raw.githubusercontent.com/critiq-dev/critiq-core/main/docs/assets/cli-architecture.png"
    alt="Cli Architecture"
  />
</p>

By default, `@critiq/cli` uses the open source [`@critiq/rules`](https://www.npmjs.com/package/@critiq/rules) catalog with recommended rules. You can customize which rules are used either by passing command-line flags or by creating a `.critiq/config.yaml` configuration file.

<br/>
<p align="left">
  <img
    src="https://raw.githubusercontent.com/critiq-dev/critiq-core/main/docs/assets/languages.png"
    alt="TypeScript, JavaScript, Node.js, Go, Java, Python, PHP, Ruby and Rust support"
  />
</p>

`@critiq/cli` is capable of scanning codebases written in TypeScript, JavaScript, Node.js, Go, Java, Python, PHP, Ruby, and Rust. 

## Start In 60 Seconds

Run Critiq on your project:

```bash
npm install -D @critiq/cli @critiq/rules
npx @critiq/cli check .
```

Run Critiq against a diff:

```bash
npx @critiq/cli check . --base origin/main --head HEAD
```

## GitHub Actions

To run the same checks on **pull requests** in GitHub Actions, with optional **inline PR review comments** and severity-based merge gates, use the official composite action **[critiq-dev/critiq-action](https://github.com/critiq-dev/critiq-action)**. See the [GitHub Actions docs](https://docs.critiq.dev/ci/github-actions) for setup and configuration. The action wraps `critiq check`, honors `.critiq/config.yaml`, and can install published `@critiq/cli` / `@critiq/rules` when they are not already declared on the repository root `package.json`.

Example `.github/workflows/critiq.yml`:

```yaml
name: Critiq

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  critiq:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Critiq
        uses: critiq-dev/critiq-action@v1
        with:
          fail-on-severity: off
```

Use a **major tag** (`@v1`) or pin a **commit SHA** for supply-chain control. More options (inputs, outputs, monorepos, reusable workflow) are in the [GitHub Actions docs](https://docs.critiq.dev/ci/github-actions).

## Public Commands

`critiq check` also runs an **advisory** built-in secret scan (same scope as the rule engine, plus optional `--staged` for index-only staging review) and prints a short summary before rule results. That scan does **not** change the `critiq check` exit code; use `critiq audit secrets` for full output and for gating in CI.

**What "staged review" means**

- "Staged" means Git index content (what `git add` has queued), not all local edits.
- Critiq reads staged content the same way Git does for commit previews (`git diff --cached`).
- Use this when you want pre-commit checks to match exactly what will be committed.

| Command | What it does |
| --- | --- |
| `critiq check [target]` | Runs deterministic checks against a codebase, directory, or single file. |
| `critiq check . --base origin/main --head HEAD` | Limits scanning to changed files and changed ranges in a diff. |
| `critiq check . --staged` | Rule scan unchanged; the advisory secret scan reads only what is staged in Git index (`git diff --cached`). |
| `critiq check . --format sarif` | Exports findings as SARIF 2.1.0 for code scanning and security platforms. |
| `critiq check . --format html` | Exports a shareable HTML report for human review and audit handoff. |
| `critiq audit secrets [target]` | Runs the dedicated secret-pattern scanner (exit non-zero when matches are found). |
| `critiq audit secrets . --base origin/main --head HEAD` | Secret scan over changed files only (includes non-code paths such as `.env`). |
| `critiq audit secrets . --staged` | Secret scan over staged paths/blobs from Git index (`git diff --cached`) (pre-commit friendly). |
| `critiq audit` / `critiq audit --help` | Lists audit subcommands. |
| `critiq rules validate <glob>` | Validates rule YAML files and returns diagnostics. |
| `critiq rules test [glob]` | Runs fixture-backed `RuleSpec` files end to end. |
| `critiq rules normalize <file>` | Prints the canonical normalized form of one rule. |
| `critiq rules explain <file>` | Shows a readable breakdown of how one rule is interpreted. |

## Runtime Config

`critiq check` is catalog-first. When `.critiq/config.yaml` is present, it controls the catalog package, preset, and filters used for the run.

```yaml
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
```

Supported presets are `recommended`, `strict`, `security`, and `experimental`.

Optional `secretsScan` in the same file merges extra `ignorePaths` (in addition to top-level `ignorePaths`), disables individual detectors by id (match the `detectorId` field in JSON output; published ids are exported as `SECRETS_SCAN_DETECTOR_IDS` from `@critiq/check-runner`), and drops findings listed under `suppressFingerprints` (64 lowercase hex characters from JSON `fingerprint`).

## Git hooks

Sample scripts ship under `scripts/hooks/` in this package (for example `pre-commit.sample.sh` runs `critiq audit secrets . --staged`; `pre-push.sample.sh` runs a diff against `origin/main` or `CRITIQ_PRE_PUSH_BASE`). Copy one to `.git/hooks/` and mark it executable, or wire the same commands into Husky.

## Default OSS Rule Catalog

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

## Reference

- [critiq.dev](https://critiq.dev) — product site
- [docs.critiq.dev](https://docs.critiq.dev) — full documentation
- [Getting started](https://docs.critiq.dev/getting-started)
- [CLI reference](https://docs.critiq.dev/cli)
- [GitHub Actions](https://docs.critiq.dev/ci/github-actions)
- [`@critiq/rules` package](https://www.npmjs.com/package/@critiq/rules)

## License

`@critiq/cli` is licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0). See the source [LICENSE](https://github.com/critiq-dev/critiq-core/blob/main/LICENSE).
