# Semantic Validation Reference

`CRQ-OSS-06` adds semantic validation for source-aware loaded rule documents in
`@critiq/core-rules-dsl`.

## Validation Layers

Rule processing is split into three phases:

1. YAML loading: `loadRuleText()` / `loadRuleFile()`
2. Contract validation: `validateLoadedRuleDocumentContract()`
3. Semantic validation: `validateRuleDocumentSemantics()`

`validateLoadedRuleDocument()` and `validateRuleTextDocument()` compose the
contract and semantic phases for convenience.

## Semantic Rules in v0

- `metadata.id` must use either a dotted slug or another semantically approved
  catalog identifier
- `all` must be non-empty
- `any` must be non-empty
- `bind` names must be unique within the same logical branch
- `scope.languages` must be non-empty
- emit content must contain at least one non-blank user-facing message field
- placeholders may only reference supported `captures`, `file`, and `rule`
  variables
- capture placeholders must reference captures that are reachable from the rule
  condition tree
- `metadata.references[].id` must match kind-specific patterns for `cwe`, `cve`,
  and `advisory`
- `metadata.references[].url` must use `http://` or `https://` when present
- `metadata.detection.kind: vulnerability` requires a top-level `vulnerability`
  block and vice versa
- `vulnerability` rules require `classification`, `issueKind`, `package.name`,
  `package.affectedVersions`, `fix.kind`, `fix.available`, and `fix.summary`
- CVE issue kinds require `vulnerability.ids.cve` or `vulnerability.ids.advisory`
- upgrade fixes with `fix.available: true` require `fix.versions`
- security-category rules without `metadata.references` emit a warning
- OSS catalog rules must not declare `vulnerability`

## Branch Semantics

- `all` accumulates captures from left to right
- `any` validates each branch independently and only exposes captures present in
  every branch
- `not` validates its child branch but does not expose captures outward

## Supported Template Variables

- `${captures.<name>.text}`
- `${captures.<name>.kind}`
- `${captures.<name>.path}`
- `${file.path}`
- `${file.language}`
- `${rule.id}`
- `${rule.title}`

Placeholders are validated in:

- `emit.message.title`
- `emit.message.summary`
- `emit.message.detail`
- `emit.remediation.summary`

## Diagnostic Codes

- `semantic.rule-id.invalid`
- `semantic.logical.empty-all`
- `semantic.logical.empty-any`
- `semantic.capture.duplicate-bind`
- `semantic.capture.unreachable-reference`
- `semantic.template.invalid-variable`
- `semantic.scope.languages.empty`
- `semantic.emit.empty`

## Example

```ts
const loaded = loadRuleText(text, 'file:///rules/example.yaml');

if (loaded.success) {
  const contract = validateLoadedRuleDocumentContract(loaded.data);

  if (contract.success) {
    const semantic = validateRuleDocumentSemantics(contract.data);
    console.log(semantic.diagnostics);
  }
}
```
