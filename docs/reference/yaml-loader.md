# YAML Loader Reference

`CRQ-OSS-05` introduces a YAML-backed source-aware rule loading flow.

## Public Rule Loader API

The public rule-facing APIs live in `@critiq/core-rules-dsl`:

- `loadRuleText(text, uri)`
- `loadRuleFile(path)`

Successful results return:

- `uri`
- `document`
- `sourceMap`

Failed results return:

- `diagnostics`

## Source Map Model

Source mappings use a sidecar pointer index rather than wrapping every value.

Each JSON Pointer entry may contain:

- `keySpan`
- `valueSpan`

Pointers are deterministic and RFC 6901 compatible. The root document span is
always addressable at `/`.

Examples:

- `/metadata/id`
- `/match`
- `/emit/message/title`
- `/scope/languages/0`

## Diagnostic Behavior

User-facing YAML problems are translated into diagnostics with exact source
locations:

- `yaml.syntax.invalid`
- `yaml.mapping.duplicate-key`
- `runtime.internal.error`

Multi-document YAML is rejected in v0 and reported as a loader diagnostic.

## Example Span Lookups

```ts
const result = loadRuleText(text, 'file:///rules/example.yaml');

if (result.success) {
  result.data.sourceMap['/metadata/id'];
  result.data.sourceMap['/match'];
  result.data.sourceMap['/emit/message/title'];
}
```
