# Template Variables Reference

`CRQ-OSS-11` uses the semantic-validated v0 variable set at runtime in
`@critiq/core-rules-engine`.

## Supported Variables

- `${captures.<name>.text}`
- `${captures.<name>.kind}`
- `${captures.<name>.path}`
- `${file.path}`
- `${file.language}`
- `${rule.id}`
- `${rule.title}`

## Rendering Rules

- placeholders must use the exact `${...}` form
- no code execution is supported
- no fallback syntax is supported
- missing or unsupported variables return structured render issues
- rendering does not partially silence failures

## API

- `renderMessageTemplate(template, rule, analyzedFile, match)`

## Result Shape

- `{ success: true, text }`
- `{ success: false, issues }`

Issue codes:

- `invalid-template`
- `unknown-variable`
