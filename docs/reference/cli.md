# CLI Reference

`critiq` has two public surfaces:

- `critiq check` for running confidence checks against real repository code
- `critiq rules ...` for authoring, validating, inspecting, and testing rule
  packs

The design goal is simple: the same deterministic contracts should work for a
developer at a terminal and for CI guarding code on the way to production.

## Commands

- `critiq check [target]`
- `critiq rules validate <glob>`
- `critiq rules test [glob]`
- `critiq rules normalize <file>`
- `critiq rules explain <file>`

## Shared Flags

- `--format pretty|json`
- `--help`

`pretty` is the default.

`critiq check` also supports:

- `--base <git-ref>`
- `--head <git-ref>`

Provide `--base` and `--head` together when you want a diff-scoped scan.

## Exit Codes

- `0`: success
- `1`: findings or non-internal command failures
- `2`: internal or runtime errors

## Runtime Config

`critiq check` is catalog-first. It reads `.critiq/config.yaml` when present
and uses it to decide which catalog, preset, and filters are active.

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

Behavior notes:

- `catalog.package` is optional and defaults to `@critiq/rules` in the OSS
  runtime
- supported presets are `recommended`, `strict`, `security`, and
  `experimental`
- `disableCategories` accepts top-level categories such as `security` and
  dotted subcategories such as `security.injection`
- `disableLanguages` can exclude languages even when adapters are registered
- tests are excluded from `check` by default unless `includeTests: true`
- legacy `critiq check "<rules-glob>" .` usage is rejected

## `check`

Use `check` when you want Critiq to measure confidence on actual repository
code instead of validating the rule pack itself.

High-level flow:

1. resolve the target path and optional diff scope
2. load `.critiq/config.yaml`
3. resolve the configured catalog package and preset
4. discover repository files and apply ignore rules
5. detect repository languages and keep only active rules
6. analyze supported source files through registered adapters
7. augment analysis with repo-level heuristics
8. emit canonical findings, summaries, diagnostics, and a stable exit code

Examples:

```bash
critiq check
critiq check . --format json
critiq check . --base origin/main --head HEAD --format json
```

Current runtime behavior:

- `target` defaults to `.`
- scans can run against a directory or a single file
- diff mode limits scope to changed files and changed ranges
- findings are emitted with evidence, provenance, confidence, and fingerprints
- repo-level augmentation currently adds heuristics for auth and ownership
  coverage, route mismatches, repeated IO in loops, batching opportunities,
  duplicated large logic, direct import cycles, and test coverage gaps

### Language Coverage

- TypeScript and JavaScript have the deepest adapter support today.
- Go, Java, PHP, Python, Ruby, and Rust are included through early phase-1
  adapters with narrower analysis coverage.

### `check` JSON Envelope

Abridged shape:

```json
{
  "command": "check",
  "format": "json",
  "target": ".",
  "catalogPackage": "@critiq/rules",
  "preset": "recommended",
  "scope": {
    "mode": "repo"
  },
  "provenance": {
    "engineKind": "critiq-cli",
    "engineVersion": "0.0.1",
    "generatedAt": "2026-04-28T12:00:00.000Z"
  },
  "scannedFileCount": 12,
  "matchedRuleCount": 5,
  "findingCount": 3,
  "findings": [],
  "ruleSummaries": [],
  "diagnostics": [],
  "exitCode": 1
}
```

## `rules validate`

Use `validate` while authoring or reviewing a rule pack.

It loads YAML, validates the public contract, runs semantic validation, and
returns diagnostics only.

Examples:

```bash
critiq rules validate ".critiq/rules/*.rule.yaml"
critiq rules validate "packages/my-pack/rules/*.rule.yaml" --format json
```

Abridged JSON envelope:

```json
{
  "command": "rules.validate",
  "format": "json",
  "target": ".critiq/rules/*.rule.yaml",
  "matchedFileCount": 2,
  "results": [],
  "diagnostics": [],
  "exitCode": 0
}
```

## `rules test`

Use `test` to run fixture-backed `RuleSpec` files end to end.

This is the primary way to prove that a rule behaves the way you expect before
you trust it in CI.

Examples:

```bash
critiq rules test
critiq rules test ".critiq/rules/*.spec.yaml"
```

When no glob is provided, the command defaults to `**/*.spec.yaml`.

Abridged JSON envelope:

```json
{
  "command": "rules.test",
  "format": "json",
  "target": "**/*.spec.yaml",
  "matchedFileCount": 5,
  "results": [],
  "diagnostics": [],
  "exitCode": 0
}
```

## `rules normalize`

Use `normalize` when you want the canonical normalized IR for one concrete
rule file.

Example:

```bash
critiq rules normalize .critiq/rules/no-console.rule.yaml --format json
```

Abridged JSON envelope:

```json
{
  "command": "rules.normalize",
  "format": "json",
  "file": {
    "path": "rule.yaml",
    "uri": "file:///workspace/rule.yaml"
  },
  "normalizedRule": {},
  "ruleHash": "sha256-value",
  "diagnostics": [],
  "exitCode": 0
}
```

## `rules explain`

Use `explain` when you want a readable breakdown of what Critiq thinks a rule
means before it is executed in a larger pack.

The output includes:

- parsed summary
- semantic status
- normalized rule
- inferred template variables

Example:

```bash
critiq rules explain .critiq/rules/no-console.rule.yaml
```

Abridged JSON envelope:

```json
{
  "command": "rules.explain",
  "format": "json",
  "file": {
    "path": "rule.yaml",
    "uri": "file:///workspace/rule.yaml"
  },
  "parsedSummary": {},
  "semanticStatus": {},
  "normalizedRule": {},
  "ruleHash": "sha256-value",
  "templateVariables": {},
  "diagnostics": [],
  "exitCode": 0
}
```

## CI Workflow

This repository publishes a reusable workflow at
`.github/workflows/run-critiq-cli.yml`.

Use it when you want consumer repositories to:

- install a pinned `critiq` package version
- run `check`, `validate`, and `test` with JSON output
- upload Critiq result artifacts
- fail the job when any Critiq command exits non-zero
