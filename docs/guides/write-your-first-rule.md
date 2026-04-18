# Write Your First Rule

Start from an existing local rule or from the maintained examples in the
separate `critiq-rules` repository.

## Workflow

1. Copy an existing `.rule.yaml` and `.spec.yaml` pair into `.critiq/rules/`.
2. Rename the rule `metadata.id` and update the human-facing text.
3. Add one `invalid` source fixture that should emit a finding.
4. Add one `valid` source fixture that should not emit a finding.
5. Run:

```bash
critiq rules validate ".critiq/rules/*.rule.yaml"
critiq rules explain .critiq/rules/no-console.rule.yaml
critiq rules test ".critiq/rules/*.spec.yaml"
```

## Good Starter Examples

- `ts.logging.no-console-log` for a simple `node.where` rule
- `ts.logging.no-console-error` for `not` plus `ancestor`
- `ts.config.no-process-env-outside-config` for path scoping

You can find maintained versions of those examples in `critiq-rules`.
