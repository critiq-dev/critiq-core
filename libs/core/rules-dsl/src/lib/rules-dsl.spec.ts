import {
  assertValidRuleDocument,
  isRuleDocument,
  RULE_DOCUMENT_KIND,
  RULE_DOCUMENT_V0_ALPHA1_API_VERSION,
  ruleDocumentV0Alpha1Schema,
  type RuleDocumentV0Alpha1,
  validateRuleDocument,
} from '../index';

const minimalRule =
  require('../../examples/rule-minimal.valid.json') as RuleDocumentV0Alpha1;
const fullRule =
  require('../../examples/rule-full.valid.json') as RuleDocumentV0Alpha1;

describe('ruleDocumentV0Alpha1Schema', () => {
  it('validates the minimal example rule', () => {
    expect(validateRuleDocument(minimalRule)).toEqual({
      success: true,
      data: minimalRule,
    });
  });

  it('validates the canonical full example rule', () => {
    expect(validateRuleDocument(fullRule)).toEqual({
      success: true,
      data: fullRule,
    });
  });

  it('validates the architecture-doc DSL example unchanged', () => {
    expect(ruleDocumentV0Alpha1Schema.parse(fullRule)).toEqual(fullRule);
  });

  it('narrows with isRuleDocument()', () => {
    const candidate: unknown = minimalRule;

    if (!isRuleDocument(candidate)) {
      throw new Error('Expected minimal rule to validate.');
    }

    expect(candidate.apiVersion).toBe(RULE_DOCUMENT_V0_ALPHA1_API_VERSION);
    expect(candidate.kind).toBe(RULE_DOCUMENT_KIND);
  });

  it('allows assertValidRuleDocument() to pass for valid input', () => {
    expect(() => {
      assertValidRuleDocument(fullRule);
    }).not.toThrow();
  });

  it('rejects missing required top-level sections', () => {
    const result = validateRuleDocument({
      ...minimalRule,
      emit: undefined,
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/emit',
          code: 'invalid_type',
        }),
      ]),
    });
  });

  it('rejects missing required metadata fields', () => {
    const result = validateRuleDocument({
      ...minimalRule,
      metadata: {
        ...minimalRule.metadata,
        summary: undefined,
      },
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/metadata/summary',
          code: 'invalid_type',
        }),
      ]),
    });
  });

  it('rejects missing required emit fields', () => {
    const result = validateRuleDocument({
      ...minimalRule,
      emit: {
        ...minimalRule.emit,
        message: {
          ...minimalRule.emit.message,
          title: undefined,
        },
      },
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/emit/message/title',
          code: 'invalid_type',
        }),
      ]),
    });
  });

  it('accepts metadata.id values at the contract layer and defers format checks to semantics', () => {
    const result = validateRuleDocument(
      require('../../examples/rule-invalid.bad-id.json'),
    );

    expect(result.success).toBe(true);
  });

  it('accepts OSS taxonomy fields at the contract layer', () => {
    const result = validateRuleDocument({
      ...minimalRule,
      metadata: {
        ...minimalRule.metadata,
        id: 'ts.security.no-sql-interpolation',
        stability: 'stable',
        appliesTo: 'block',
      },
      scope: {
        languages: ['all'],
      },
      emit: {
        ...minimalRule.emit,
        finding: {
          ...minimalRule.emit.finding,
          category: 'security.injection',
          severity: 'critical',
          confidence: 0.95,
        },
      },
    });

    expect(result.success).toBe(true);
  });

  it('rejects unsupported comparison operators', () => {
    const result = validateRuleDocument(
      require('../../examples/rule-invalid.unsupported-operator.json'),
    );

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/match',
          code: 'invalid_union',
        }),
      ]),
    });
  });

  it('rejects extra top-level fields', () => {
    const result = validateRuleDocument(
      require('../../examples/rule-invalid.extra-top-level.json'),
    );

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/',
          code: 'unrecognized_keys',
          received: 'unexpectedField',
        }),
      ]),
    });
  });

  it('rejects extra nested fields', () => {
    const result = validateRuleDocument({
      ...minimalRule,
      match: {
        node: {
          kind: 'CallExpression',
          extra: true,
        },
      },
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/match/node',
          code: 'unrecognized_keys',
          received: 'extra',
        }),
      ]),
    });
  });

  it('rejects invalid kind values', () => {
    const result = validateRuleDocument({
      ...minimalRule,
      kind: 'Finding',
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/kind',
          code: 'invalid_literal',
        }),
      ]),
    });
  });

  it('rejects invalid apiVersion values', () => {
    const result = validateRuleDocument({
      ...minimalRule,
      apiVersion: 'critiq.dev/v1',
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/apiVersion',
          code: 'invalid_literal',
        }),
      ]),
    });
  });
});
