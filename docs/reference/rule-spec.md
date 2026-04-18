# RuleSpec Reference

`RuleSpec` is the fixture-based test contract consumed by
`@critiq/testing-harness` and `critiq rules test`.

## Top-Level Shape

```yaml
apiVersion: critiq.dev/v1alpha1
kind: RuleSpec
rulePath: ./example.rule.yaml
fixtures:
  - name: flags bad usage
    sourcePath: ./fixtures/invalid.ts
    expect:
      findingCount: 1
```

## Fixture Sources

Each fixture must declare exactly one of:

- `sourcePath`
- `observationPath`

Paths are resolved relative to the spec file directory.

For source fixtures, the harness currently infers the adapter from the file
extension:

- `.ts`
- `.tsx`
- `.js`
- `.jsx`

Observation fixtures may include semantic adapter output such as
`semantics.controlFlow` when a rule depends on fact-backed evaluation.

## Assertions

The v0 harness supports:

- `findingCount`
- `allRuleIds`
- `allSeverities`
- `titleContains`
- `summaryContains`
- `primaryLocation.line`
- `primaryLocation.column`

`allSeverities` accepts `low`, `medium`, `high`, and `critical`.
