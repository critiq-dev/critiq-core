# CLI Reference

`critiq` supports both rule authoring commands and repository scanning.

## Commands

- `critiq check [target]`
- `critiq rules validate <glob>`
- `critiq rules test [glob]`
- `critiq rules normalize <file>`
- `critiq rules explain <file>`

## Output Formats

- `pretty`
- `json`

`pretty` is the default.

## Exit Codes

- `0`: success
- `1`: user/input errors or validation diagnostics
- `2`: internal/runtime errors

## Check

`check` is catalog-first. It loads `.critiq/config.yaml`, resolves the
configured catalog package, selects the configured preset, applies subtractive
overrides, auto-detects repository languages from supported source files, and
runs the active rules against the target.

- `target` defaults to `.`
- `--base` and `--head` enable diff-scoped scans against changed files only
- supported source extensions in v1: `.ts`, `.tsx`, `.js`, `.jsx`
- legacy `critiq check "<rules-glob>" .` usage is rejected with a migration error

JSON output envelope:

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
  "scannedFileCount": 12,
  "matchedRuleCount": 5,
  "findingCount": 3,
  "findings": [],
  "ruleSummaries": [],
  "diagnostics": [],
  "exitCode": 1
}
```

## Validate

`validate` accepts a single file or a glob and returns diagnostics only.

JSON output envelope:

```json
{
  "command": "rules.validate",
  "format": "json",
  "target": "*.rule.yaml",
  "matchedFileCount": 2,
  "results": [],
  "diagnostics": [],
  "exitCode": 1
}
```

## Normalize

`normalize` requires one concrete file and prints canonical normalized IR.

JSON output envelope:

```json
{
  "command": "rules.normalize",
  "format": "json",
  "file": {
    "path": "rule.yaml",
    "uri": "file:///workspace/rule.yaml"
  },
  "parsedSummary": {},
  "semanticStatus": {},
  "normalizedRule": {},
  "ruleHash": "sha256-value",
  "diagnostics": [],
  "exitCode": 0
}
```

## Test

`test` discovers `RuleSpec` files, runs fixtures through the harness, and
returns stable pass/fail results.

When no glob is provided it defaults to `**/*.spec.yaml`.

JSON output envelope:

```json
{
  "command": "rules.test",
  "format": "json",
  "target": "**/*.spec.yaml",
  "matchedFileCount": 5,
  "results": [
    {
      "specPath": ".critiq/rules/no-console.spec.yaml",
      "success": true,
      "result": {
        "fixtureResults": []
      }
    }
  ],
  "diagnostics": [],
  "exitCode": 0
}
```

## Explain

`explain` requires one concrete file and prints:

- parsed summary
- semantic status
- normalized rule
- inferred template variables

JSON output envelope:

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
