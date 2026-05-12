<p align="center">
  <img src="https://raw.githubusercontent.com/critiq-dev/critiq-core/main/docs/assets/banner-cli-simple-transparent.png" alt="critiq.dev" style="max-height:400px" />
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
    src="https://raw.githubusercontent.com/critiq-dev/critiq-core/main/docs/assets/cli-architecture-transparent.png"
    alt="Cli Architecture"
  />
</p>

`@critiq/cli` runs Critiq checks against real code and exposes the public rule-pack commands for validation, testing, normalization, and explanation. By default it uses [`@critiq/rules`](https://www.npmjs.com/package/@critiq/rules) as the open source catalog with recommended rules. You can configure this by adding a `.critiq/config.yaml` configuration file.

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
npx critiq check .
```

Run Critiq against a diff:

```bash
npx critiq check . --base origin/main --head HEAD
```

## Public Commands

`critiq check` also runs an **advisory** built-in secret scan (same scope as the rule engine) and prints a short summary before rule results. That scan does **not** change the `critiq check` exit code; use `critiq audit secrets` for full output and for gating in CI.

| Command | What it does |
| --- | --- |
| `critiq check [target]` | Runs deterministic checks against a codebase, directory, or single file. |
| `critiq check . --base origin/main --head HEAD` | Limits scanning to changed files and changed ranges in a diff. |
| `critiq audit secrets [target]` | Runs the dedicated secret-pattern scanner (exit non-zero when matches are found). |
| `critiq audit secrets . --base origin/main --head HEAD` | Secret scan over changed files only (includes non-code paths such as `.env`). |
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

## Default OSS Rule Catalog

The default open source catalog in [`@critiq/rules`](https://www.npmjs.com/package/@critiq/rules) currently includes `112` rules across `10` categories.

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

- [Getting started](https://github.com/critiq-dev/critiq-core/blob/main/docs/guides/getting-started.md)
- [CLI reference](https://github.com/critiq-dev/critiq-core/blob/main/docs/reference/cli.md)
- [`@critiq/rules` package](https://www.npmjs.com/package/@critiq/rules)

## License

`@critiq/cli` is licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0). See the source [LICENSE](https://github.com/critiq-dev/critiq-core/blob/main/LICENSE).
