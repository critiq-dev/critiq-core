# @critiq/util-yaml-loader

Generic UTF-8 YAML parsing helpers with deterministic source mapping.

This package stays parser-focused and reusable. It does not know about the Critiq
rule contract or diagnostics package. Instead, it returns plain JavaScript
values, a pointer-indexed source map, and generic YAML load issues that core
packages can translate into user-facing diagnostics.

## Exports

- `loadYamlText()`
- `YamlLoadResult`
- `YamlLoadIssue`
- `YamlSourceMap`
- `YamlSourceMapEntry`

## Behavior

- accepts UTF-8 YAML text
- rejects multi-document YAML in v0
- rejects duplicate keys
- preserves source spans for nested mappings, sequences, and scalars

## Example

```ts
import { loadYamlText } from '@critiq/util-yaml-loader';

const result = loadYamlText('metadata:\n  id: example.rule', 'file:///rule.yaml');

if (result.success) {
  console.log(result.sourceMap['/metadata/id']);
}
```

Allowed dependencies: `type:util`
