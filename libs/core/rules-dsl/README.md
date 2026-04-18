# @critiq/core-rules-dsl

The canonical v0 alpha authoring contract for Critiq rules. This package defines the stable `RuleDocumentV0Alpha1` schema, validates authored rule documents at runtime, and publishes a checked-in JSON Schema artifact for tooling and external consumers.

## Exports

- `RuleDocumentV0Alpha1` and supporting nested contract types
- `ruleDocumentV0Alpha1Schema`
- `ruleDocumentV0Alpha1JsonSchema`
- `validateRuleDocument()`
- `assertValidRuleDocument()`
- `isRuleDocument()`
- `loadRuleText()`
- `loadRuleFile()`
- `validateLoadedRuleDocumentContract()`
- `validateRuleDocumentSemantics()`
- `validateLoadedRuleDocument()`
- `validateRuleTextDocument()`
- `validateRuleFileDocument()`
- `summarizeValidatedRuleDocument()`
- `inferRuleTemplateVariables()`
- source-aware rule loader result types and pointer-indexed source map types
- semantic diagnostic code constants
- `RULE_DOCUMENT_V0_ALPHA1_API_VERSION`
- `RULE_DOCUMENT_KIND`

API version: `critiq.dev/v1alpha1`

Kind: `Rule`

## Validation Example

```ts
import { validateRuleDocument } from '@critiq/core-rules-dsl';

const result = validateRuleDocument({
  apiVersion: 'critiq.dev/v1alpha1',
  kind: 'Rule',
  metadata: {
    id: 'ts.security.no-dynamic-execution',
    title: 'Eval or dynamic code execution',
    summary: 'Dynamic execution helpers should not run application input.',
    stability: 'stable',
    appliesTo: 'block',
  },
  scope: {
    languages: ['typescript', 'javascript'],
  },
  match: {
    node: {
      kind: 'CallExpression',
      bind: 'dynamicExecution',
    },
  },
  emit: {
    finding: {
      category: 'security.execution',
      severity: 'high',
      confidence: 0.95,
    },
    message: {
      title: 'Avoid eval or Function execution',
      summary: 'Replace `${captures.dynamicExecution.text}` with explicit logic.',
    },
  },
});

if (!result.success) {
  console.error(result.issues);
}
```

## YAML Loading Example

```ts
import { loadRuleText } from '@critiq/core-rules-dsl';

const result = loadRuleText('metadata:\n  id: ts.logging.no-console-log', 'file:///rules/example.yaml');

if (result.success) {
  console.log(result.data.sourceMap['/metadata/id']);
} else {
  console.error(result.diagnostics);
}
```

## Semantic Validation Example

```ts
import { loadRuleText, validateLoadedRuleDocument } from '@critiq/core-rules-dsl';

const loaded = loadRuleText(ruleYamlText, 'file:///rules/example.yaml');

if (!loaded.success) {
  console.error(loaded.diagnostics);
} else {
  const result = validateLoadedRuleDocument(loaded.data);

  if (!result.success) {
    console.error(result.diagnostics);
  }
}
```

`metadata.id` shape and template reachability are semantic rules in v0. Shipped
rules use dotted slugs like `ts.logging.no-console-log`. These checks run after
YAML loading and contract validation so diagnostics can carry JSON pointers and
source spans.

## Explain Helper Example

```ts
import { loadRuleText, summarizeValidatedRuleDocument, validateLoadedRuleDocumentContract } from '@critiq/core-rules-dsl';

const loaded = loadRuleText(ruleYamlText, 'file:///rules/example.yaml');

if (loaded.success) {
  const contract = validateLoadedRuleDocumentContract(loaded.data);

  if (contract.success) {
    console.log(summarizeValidatedRuleDocument(contract.data).templateVariables);
  }
}
```

## Commands

- `npm run nx -- run rules-dsl:generate-schema`
- `npm run nx -- build rules-dsl`
- `npm run nx -- test rules-dsl`
- `npm run nx -- lint rules-dsl`
