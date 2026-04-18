# Getting Started

This guide is the fastest path from clone to a working mental model of the
repository.

## Who This Guide Is For

Use this if:

- you are new to Critiq Core
- you want to run the repo locally before reading all the references
- you want to understand the normal author workflow

## 1. Install

Requirements:

- Node.js 20+
- npm 10+

Install dependencies:

```bash
npm install
```

## 2. Verify The Workspace

Run the standard gate once so you know the workspace is healthy:

```bash
npm run verify
```

Optional but useful:

```bash
npm run nx -- graph
```

## 3. Build The CLI

```bash
npm run nx -- run cli:prune
```

The built entrypoint is:

```bash
node dist/apps/cli/main.js
```

## 4. Run The Default OSS Catalog

Run the default public catalog against this repository:

```bash
mkdir -p .critiq
cat > .critiq/config.yaml <<'EOF'
apiVersion: critiq.dev/v1alpha1
kind: CritiqConfig
catalog:
  package: "@critiq/rules"
preset: recommended
EOF
node dist/apps/cli/main.js check .
```

If you also cloned the sibling `critiq-rules` repo, validate the starter pack:

```bash
node dist/apps/cli/main.js rules validate "../critiq-rules/examples/starter-pack/rules/*.rule.yaml"
```

Explain one starter rule:

```bash
node dist/apps/cli/main.js rules explain ../critiq-rules/examples/starter-pack/rules/ts.logging.no-console-log.rule.yaml
```

Run the fixture-based tests:

```bash
node dist/apps/cli/main.js rules test "../critiq-rules/examples/starter-pack/rules/*.spec.yaml"
```

This shows the whole local author loop:

- rule loading
- validation
- normalization
- explanation
- fixture-based execution

## 5. Learn The Main Packages

You do not need to read every package in depth. Start here:

- `libs/core/rules-dsl`
  How rules are authored, loaded, and validated.
- `libs/core/ir`
  How valid rules normalize into deterministic IR.
- `libs/core/rules-engine`
  How normalized rules evaluate against analyzed files and become findings.
- `tools/testing/harness`
  How `RuleSpec` executes fixtures.
- `libs/adapters/typescript`
  How real `.ts/.js/.tsx/.jsx` files become the observation model.

## 6. Pick Your Next Path

### I want to author rules

Read:

- [write-your-first-rule.md](./write-your-first-rule.md)
- [rule-dsl-v0alpha1.md](../reference/rule-dsl-v0alpha1.md)
- [rule-spec.md](../reference/rule-spec.md)

### I want to contribute runtime code

Read:

- [../../CONTRIBUTING.md](../../CONTRIBUTING.md)
- [../architecture/repo-map.md](../architecture/repo-map.md)
- [../architecture/ecosystem.md](../architecture/ecosystem.md)

### I want to understand compatibility and release expectations

Read:

- [../reference/versioning-policy.md](../reference/versioning-policy.md)
- [../reference/release-process.md](../reference/release-process.md)
