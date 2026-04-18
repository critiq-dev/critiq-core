import {
  DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
} from '@critiq/core-diagnostics';

import {
  DIAGNOSTIC_CODE_RULE_SEMANTIC_CAPTURE_DUPLICATE_BIND,
  DIAGNOSTIC_CODE_RULE_SEMANTIC_CAPTURE_UNREACHABLE_REFERENCE,
  DIAGNOSTIC_CODE_RULE_SEMANTIC_EMIT_EMPTY,
  DIAGNOSTIC_CODE_RULE_SEMANTIC_LOGICAL_EMPTY_ALL,
  DIAGNOSTIC_CODE_RULE_SEMANTIC_LOGICAL_EMPTY_ANY,
  DIAGNOSTIC_CODE_RULE_SEMANTIC_MATCH_MIXED_DOMAINS,
  DIAGNOSTIC_CODE_RULE_SEMANTIC_RULE_ID_INVALID,
  DIAGNOSTIC_CODE_RULE_SEMANTIC_SCOPE_LANGUAGES_EMPTY,
  DIAGNOSTIC_CODE_RULE_SEMANTIC_TEMPLATE_INVALID_VARIABLE,
  loadRuleText,
  validateLoadedRuleDocument,
  validateLoadedRuleDocumentContract,
  validateRuleDocumentSemantics,
  validateRuleTextDocument,
  type ContractValidatedRuleDocument,
  type LoadedRuleDocument,
} from '../index';

function loadYamlRule(text: string, uri = 'file:///rules/test.yaml'): LoadedRuleDocument {
  const result = loadRuleText(text, uri);

  if (!result.success) {
    throw new Error(`Expected YAML to load successfully: ${JSON.stringify(result.diagnostics)}`);
  }

  return result.data;
}

function contractValidate(text: string, uri?: string): ContractValidatedRuleDocument {
  const loaded = loadYamlRule(text, uri);
  const result = validateLoadedRuleDocumentContract(loaded);

  if (!result.success) {
    throw new Error(`Expected contract validation success: ${JSON.stringify(result.diagnostics)}`);
  }

  return result.data;
}

describe('rule semantic validation', () => {
  it('passes contract and semantic validation for a minimal valid rule', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log',
        '  summary: Use the logger',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        '    bind: call',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Avoid console.log',
        '    summary: Found `${captures.call.text}` in `${file.path}`.',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: true,
      diagnostics: [],
    });
    expect(validateLoadedRuleDocument(document)).toEqual({
      success: true,
      data: document,
      diagnostics: [],
    });
  });

  it('passes unchanged for the canonical full rule shape', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log',
        '  summary: Use the logger',
        'scope:',
        '  languages:',
        '    - typescript',
        '    - javascript',
        'match:',
        '  all:',
        '    - node:',
        '        kind: CallExpression',
        '        bind: call',
        '        where:',
        '          - path: callee.object.text',
        '            equals: console',
        '    - not:',
        '        ancestor:',
        '          kind: CatchClause',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Avoid `${captures.call.kind}`',
        '    summary: Found `${captures.call.text}` in `${file.path}`.',
        '    detail: Rule `${rule.id}` triggered for `${file.language}`.',
        '  remediation:',
        '    summary: Replace with logger.info',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: true,
      diagnostics: [],
    });
  });

  it('accepts OSS catalog ids and taxonomy metadata', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.security.no-sql-interpolation',
        '  title: SQL query built via string concatenation',
        '  summary: SQL statements must not interpolate untrusted input.',
        '  stability: stable',
        '  appliesTo: block',
        'scope:',
        '  languages:',
        '    - typescript',
        '    - javascript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        '    bind: query',
        'emit:',
        '  finding:',
        '    category: security.injection',
        '    severity: high',
        '    confidence: 0.95',
        '  message:',
        '    title: Avoid interpolated SQL',
        '    summary: Use placeholders instead of `${captures.query.text}`',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: true,
      diagnostics: [],
    });
  });

  it('allows duplicate bind names in separate any branches', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.any-branches',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  any:',
        '    - node:',
        '        kind: CallExpression',
        '        bind: call',
        '    - node:',
        '        kind: NewExpression',
        '        bind: call',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Example',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: true,
      diagnostics: [],
    });
  });

  it('accepts fact-backed rules that bind semantic observations', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.correctness.unreachable-statement',
        '  title: Unreachable code after return or throw',
        '  summary: Statements after terminal exits should be removed.',
        '  appliesTo: block',
        'scope:',
        '  languages:',
        '    - typescript',
        '    - javascript',
        'match:',
        '  fact:',
        '    kind: control-flow.unreachable-statement',
        '    bind: issue',
        '    where:',
        '      - path: reason',
        '        in:',
        '          - after-return',
        '          - after-throw',
        'emit:',
        '  finding:',
        '    category: correctness.control-flow',
        '    severity: low',
        '    confidence: 0.95',
        '  message:',
        '    title: Remove unreachable statement',
        '    summary: Review `${captures.issue.text}` in `${file.path}`.',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: true,
      diagnostics: [],
    });
  });

  it('rejects rules that mix syntax predicates with fact predicates', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.correctness.invalid-mixed-match',
        '  title: Invalid',
        '  summary: Invalid',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  all:',
        '    - node:',
        '        kind: ReturnStatement',
        '    - fact:',
        '        kind: control-flow.unreachable-statement',
        'emit:',
        '  finding:',
        '    category: correctness.control-flow',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Invalid',
        '    summary: Invalid',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: false,
      diagnostics: [
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_MATCH_MIXED_DOMAINS,
          jsonPointer: '/match',
        }),
      ],
    });
  });

  it('maps contract failures back to source-aware diagnostics', () => {
    const loaded = loadYamlRule(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log',
        '  summary: Use the logger',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    summary: Missing title',
      ].join('\n'),
      'file:///rules/contract.yaml',
    );
    const result = validateLoadedRuleDocumentContract(loaded);

    expect(result.success).toBe(false);

    if (result.success) {
      throw new Error('Expected contract validation failure.');
    }

    expect(result.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
          jsonPointer: '/emit/message/title',
          sourceSpan: expect.objectContaining({
            uri: 'file:///rules/contract.yaml',
          }),
        }),
      ]),
    );
  });

  it('reports an invalid rule id semantically with source location', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: No Console Log',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Example',
      ].join('\n'),
      'file:///rules/bad-id.yaml',
    );
    const result = validateRuleDocumentSemantics(document);

    expect(result).toEqual({
      success: false,
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_RULE_ID_INVALID,
          jsonPointer: '/metadata/id',
          sourceSpan: expect.objectContaining({
            uri: 'file:///rules/bad-id.yaml',
            start: expect.objectContaining({
              line: 4,
              column: 7,
            }),
          }),
        }),
      ]),
    });
  });

  it('rejects empty all groups', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.empty-all',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  all: []',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Example',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: false,
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_LOGICAL_EMPTY_ALL,
          jsonPointer: '/match/all',
        }),
      ]),
    });
  });

  it('rejects empty any groups', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.empty-any',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  any: []',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Example',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: false,
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_LOGICAL_EMPTY_ANY,
          jsonPointer: '/match/any',
        }),
      ]),
    });
  });

  it('rejects empty language scope semantically', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-languages',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages: []',
        'match:',
        '  node:',
        '    kind: CallExpression',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Example',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: false,
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_SCOPE_LANGUAGES_EMPTY,
          jsonPointer: '/scope/languages',
        }),
      ]),
    });
  });

  it('rejects duplicate bind names in the same logical branch', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.duplicate-bind',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  all:',
        '    - node:',
        '        kind: CallExpression',
        '        bind: call',
        '    - ancestor:',
        '        kind: FunctionDeclaration',
        '        bind: call',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Example',
      ].join('\n'),
      'file:///rules/duplicate-bind.yaml',
    );
    const result = validateRuleDocumentSemantics(document);

    expect(result).toEqual({
      success: false,
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_CAPTURE_DUPLICATE_BIND,
          jsonPointer: '/match/all/1/ancestor/bind',
          sourceSpan: expect.objectContaining({
            uri: 'file:///rules/duplicate-bind.yaml',
          }),
        }),
      ]),
    });
  });

  it('rejects unknown placeholder roots', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.bad-root',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Found `${unknown.value}`',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: false,
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_TEMPLATE_INVALID_VARIABLE,
          jsonPointer: '/emit/message/summary',
        }),
      ]),
    });
  });

  it('rejects unknown placeholder fields', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.bad-field',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        '    bind: call',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Found `${captures.call.value}`',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: false,
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_TEMPLATE_INVALID_VARIABLE,
          jsonPointer: '/emit/message/summary',
        }),
      ]),
    });
  });

  it('rejects unreachable capture references under any branches', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.unreachable-any',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  any:',
        '    - node:',
        '        kind: CallExpression',
        '        bind: call',
        '    - node:',
        '        kind: NewExpression',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Found `${captures.call.text}`',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: false,
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_CAPTURE_UNREACHABLE_REFERENCE,
          jsonPointer: '/emit/message/summary',
        }),
      ]),
    });
  });

  it('rejects captures that exist only inside not branches', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.not-branch',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  all:',
        '    - not:',
        '        node:',
        '          kind: CallExpression',
        '          bind: call',
        '    - node:',
        '        kind: Identifier',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Found `${captures.call.text}`',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: false,
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_CAPTURE_UNREACHABLE_REFERENCE,
          jsonPointer: '/emit/message/summary',
        }),
      ]),
    });
  });

  it('rejects semantically empty emit content', () => {
    const document = contractValidate(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.empty-emit',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: "   "',
        '    summary: "  "',
        '  remediation:',
        '    summary: "   "',
      ].join('\n'),
    );

    expect(validateRuleDocumentSemantics(document)).toEqual({
      success: false,
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_EMIT_EMPTY,
          jsonPointer: '/emit',
        }),
      ]),
    });
  });

  it('runs the full load + contract + semantic pipeline for text input', () => {
    const result = validateRuleTextDocument(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: No Console Log',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Found `${captures.call.text}`',
      ].join('\n'),
      'file:///rules/full-pipeline.yaml',
    );

    expect(result).toEqual({
      success: false,
      diagnostics: expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_RULE_ID_INVALID,
        }),
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_RULE_SEMANTIC_CAPTURE_UNREACHABLE_REFERENCE,
        }),
      ]),
    });
  });

  it('stops at contract validation before semantic validation runs', () => {
    const result = validateRuleTextDocument(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: No Console Log',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        '    extra: true',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Found `${captures.call.text}`',
      ].join('\n'),
      'file:///rules/contract-first.yaml',
    );

    expect(result).toEqual({
      success: false,
      diagnostics: [
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
          jsonPointer: '/match/node',
        }),
      ],
    });
  });
});
