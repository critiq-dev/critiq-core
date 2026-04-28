# Getting Started

This guide gets you from clone to your first confidence check with
`critiq-core`.

Use it if you want to:

- understand what the workspace actually ships
- run the OSS confidence workflow locally before adopting it elsewhere
- contribute to the runtime, adapters, or CLI with the current architecture in
  mind

## 1. Install

Requirements:

- Node.js 20+
- npm 10+

Install dependencies:

```bash
npm install
```

## 2. Verify The Workspace

Run the standard workspace gate once:

```bash
npm run verify
```

Optional, but helpful when you are learning the workspace:

```bash
npm run nx -- graph
```

## 3. Build The Packaged CLI

```bash
npm run nx -- run cli:prune
```

Use `cli:prune` when you want the packaged runtime in `dist/`. The built
entrypoint is:

```bash
node dist/apps/cli/main.js
```

## 4. Commit A Critiq Config

`critiq check` can fall back to the default OSS catalog and the
`recommended` preset, but real adoption is clearer when the repository commits
its runtime policy in `.critiq/config.yaml`:

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

Notes:

- `catalog.package` is optional and defaults to `@critiq/rules` in the OSS
  runtime.
- tests are excluded from `check` by default; set `includeTests: true` if you
  want them in scan scope

## 5. Run A Repository Scan

Run the configured OSS catalog against this repository:

```bash
node dist/apps/cli/main.js check .
```

This is the fastest way to see the full confidence path in action:

- config loading
- catalog resolution
- preset and language filtering
- source analysis through registered adapters
- repo-level augmentation
- canonical finding output

## 6. Run A Diff-Scoped Scan

When you want the scan to focus on changed files, provide both refs:

```bash
node dist/apps/cli/main.js check . --base origin/main --head HEAD
```

Use this shape in pull request automation and pre-merge checks.

## 7. Try The Rule Authoring Loop

If you keep local rules in `.critiq/rules/`, the basic workflow is:

```bash
node dist/apps/cli/main.js rules validate ".critiq/rules/*.rule.yaml"
node dist/apps/cli/main.js rules explain .critiq/rules/no-console.rule.yaml
node dist/apps/cli/main.js rules test ".critiq/rules/*.spec.yaml"
```

If you cloned the sibling `critiq-rules` repository, point those same commands
at its example packs instead.

## 8. Understand The Runtime Surface

The most important packages to learn first are:

- `apps/cli`
  The published `critiq` command surface.
- `libs/runtime/check-runner`
  The reusable repository scan runtime behind `critiq check`.
- `libs/core/config`
  The repository-level config contract.
- `libs/core/catalog`
  Catalog loading, preset filtering, and repository-language detection.
- `libs/core/rules-dsl`
  Rule authoring, YAML loading, and semantic validation.
- `libs/core/ir`
  Canonical normalized rule form and rule hashing.
- `libs/core/rules-engine`
  Deterministic evaluation and finding construction.
- `tools/testing/harness`
  Fixture-backed `RuleSpec` execution.

## 9. Pick Your Next Doc

If you want to run the CLI in a consumer repo:

- [../reference/cli.md](../reference/cli.md)

If you want to author rules:

- [write-your-first-rule.md](./write-your-first-rule.md)
- [../reference/rule-dsl-v0alpha1.md](../reference/rule-dsl-v0alpha1.md)
- [../reference/rule-spec.md](../reference/rule-spec.md)

If you want to understand boundaries and package ownership:

- [../architecture/ecosystem.md](../architecture/ecosystem.md)
- [../architecture/repo-map.md](../architecture/repo-map.md)

If you want to contribute to the workspace itself:

- [../../CONTRIBUTING.md](../../CONTRIBUTING.md)
