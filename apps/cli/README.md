# critiq CLI

`critiq` is the local developer interface for working with Critiq rules in your
own repository.

It is designed for two equally important modes:

- manual invocation while a developer is authoring, debugging, or reviewing a rule
- automated invocation in CI to increase confidence in a PR or run a broader repository scan

Use it when you want to:

- run rules against real repository code or a PR diff
- validate authored rules before committing them
- explain how a rule is interpreted
- normalize a rule into the canonical internal form
- run fixture-based `RuleSpec` tests for a rule pack
- use the same deterministic checks locally and in automation

The CLI now has two modes:

- `critiq check` is catalog-first and loads rules from `.critiq/config.yaml`
- `critiq rules ...` commands remain path-based for pack authors and maintainers

If you want to run the built CLI from `dist/`, use:

```bash
npm run nx -- run cli:prune
node dist/apps/cli/main.js --help
```

`cli:prune` is the correct packaged-build target. `cli:build` alone does not
copy the workspace modules the runtime needs.

## Recommended Project Layout

A common consumer setup is:

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
includeTests: false
ignorePaths: []
severityOverrides: {}
```

If you are authoring your own rules, a common convention is:

```text
.critiq/
  rules/
    no-console.rule.yaml
    no-console.spec.yaml
  fixtures/
    no-console/
      valid.ts
      invalid.ts
```

This is only a convention. Authoring commands work with any file path or glob
you give them, so you can also:

- keep rules in another local folder
- vendor a shared rule pack into your repo
- install a rule pack and reference it from `.critiq/config.yaml`

## Commands

- `critiq check [target]`
- `critiq rules validate <glob>`
- `critiq rules test [glob]`
- `critiq rules normalize <file>`
- `critiq rules explain <file>`

## What Each Command Is For

### `check`

Use this to run the configured catalog against real source files in a
repository.

This is the runtime/CI entrypoint when you want Critiq to inspect application
code rather than validate or test the rule pack itself. `check` reads
`.critiq/config.yaml`, resolves the configured catalog package, applies preset
selection and subtractive overrides, auto-detects repository languages from
supported source files, and evaluates the active rules.

Today that means:

- deepest support for TypeScript and JavaScript
- early phase-1 adapter coverage for Go, Java, PHP, Python, Ruby, and Rust
- tests excluded from `check` by default unless `includeTests: true`

Examples:

```bash
critiq check
critiq check . --format json
critiq check . --base origin/main --head HEAD --format json
```

Migration:

```bash
# old
critiq check ".critiq/rules/*.rule.yaml" .

# new
critiq check .
```

### `validate`

Use this while authoring rules.

It loads the YAML, validates the public contract, runs semantic validation, and
returns diagnostics only.

This is the command you would commonly use in a PR-focused workflow to make
sure authored rules are valid before the rules are executed elsewhere.

Examples:

```bash
critiq rules validate ".critiq/rules/*.rule.yaml"
critiq rules validate "packages/my-pack/rules/*.rule.yaml"
```

### `test`

Use this to run `RuleSpec` fixtures and prove rule behavior end to end.

This is the command that gives you confidence that a rule pack behaves the way
you expect before using it in an automated PR check or a repository scan.

If you omit the glob, it defaults to `**/*.spec.yaml` from the current working
directory.

Examples:

```bash
critiq rules test
critiq rules test ".critiq/rules/*.spec.yaml"
```

### `normalize`

Use this when you want to inspect the canonical normalized IR for one rule.

Example:

```bash
critiq rules normalize .critiq/rules/no-console.rule.yaml --format json
```

### `explain`

Use this when you want a readable breakdown of:

- parsed rule metadata
- validation status
- normalized rule content
- inferred template variables

Example:

```bash
critiq rules explain .critiq/rules/no-console.rule.yaml
```

## Flags

- `--format pretty|json`
- `--help`

`pretty` is the default.

## Exit Codes

- `0`: success
- `1`: findings or non-internal command failures
- `2`: internal/runtime errors

## Typical Developer Workflow

Authoring a new rule:

```bash
npm run nx -- run cli:prune
critiq rules validate ".critiq/rules/*.rule.yaml"
critiq rules explain .critiq/rules/no-console.rule.yaml
critiq rules test ".critiq/rules/*.spec.yaml"
```

Working from the separate `critiq-rules` repo:

```bash
npm run nx -- run cli:prune
critiq rules validate "../critiq-rules/examples/starter-pack/rules/*.rule.yaml"
critiq rules explain ../critiq-rules/examples/starter-pack/rules/ts.logging.no-console-log.rule.yaml
critiq rules test "../critiq-rules/examples/starter-pack/rules/*.spec.yaml"
```

Running in automation:

```bash
npm run nx -- run cli:prune
critiq check . --format json
critiq rules validate ".critiq/rules/*.rule.yaml" --format json
critiq rules test ".critiq/rules/*.spec.yaml" --format json
```

### Reusable GitHub Workflow

Consumer repositories can call the reusable workflow published from this repo
instead of copying the CLI setup into every workflow file.

Example:

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

The workflow:

- checks out the consumer repository
- installs Node.js
- installs the requested `critiq` package version
- optionally runs `check`, `validate`, and `test` with JSON output
- uploads the JSON results as workflow artifacts

For production use, pin both the workflow ref and `critiq-version`.

## JSON Output

All commands support `--format json`.

That makes the CLI usable as:

- a terminal tool for humans
- a machine-readable step in CI
- a building block for custom wrappers

That means the same CLI can sit behind:

- a developer manually checking a rule before commit
- a repository or PR gate that emits findings from real source files
- a PR workflow that wants confidence before merge
- a scheduled or on-demand full repository scan

See [docs/reference/cli.md](../../docs/reference/cli.md) for the envelope
shapes.

## Relationship To The Rest Of The Repo

The CLI is intentionally thin. It composes the OSS packages rather than
re-implementing their logic.

- repository scanning comes from `@critiq/check-runner`
- adapter-backed source analysis comes from `@critiq/adapter-typescript`
- rule loading and validation come from `@critiq/core-rules-dsl`
- normalization comes from `@critiq/core-ir`
- diagnostics rendering comes from `@critiq/core-diagnostics`
- fixture-based testing comes from `@critiq/testing-harness`

That means you can use the CLI directly, or use the underlying packages inside
your own tooling if you need more control.

## Development Commands

- `npm run nx -- build cli`
- `npm run nx -- run cli:prune`
- `npm run nx -- test cli`
- `npm run nx -- lint cli`
- `npm run nx -- typecheck cli`
