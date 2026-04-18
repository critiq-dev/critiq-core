# @critiq/testing-harness

`@critiq/testing-harness` defines the `RuleSpec` contract and runs fixture-based
rule tests over either real source files or prebuilt observation fixtures.

## Public API

- `ruleSpecSchema`
- `validateRuleSpec(input)`
- `loadRuleSpec(path)`
- `runRuleSpec(path)`
- `formatRuleSpecRunForTerminal(result)`
- `formatRuleSpecRunAsJson(result)`

## RuleSpec v0

Each spec file declares:

- `apiVersion: critiq.dev/v1alpha1`
- `kind: RuleSpec`
- `rulePath`
- `fixtures`

Each fixture declares:

- `name`
- exactly one of `sourcePath` or `observationPath`
- `expect`

The harness currently supports these assertions:

- `findingCount`
- `allRuleIds`
- `allSeverities`
- `titleContains`
- `summaryContains`
- `primaryLocation`

## CLI

The CLI composes this package through:

```bash
critiq rules test
critiq rules test "examples/**/*.spec.yaml" --format json
```

Allowed dependencies: `type:core`, `type:adapter`, `type:util`
