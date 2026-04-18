import {
  FINDING_V0_SCHEMA_VERSION,
  assertValidFinding,
  findingV0Schema,
  isFinding,
  type FindingV0,
  validateFinding,
} from '../index';

const minimalFinding =
  require('../../examples/finding-minimal.valid.json') as FindingV0;
const richFinding =
  require('../../examples/finding-rich.valid.json') as FindingV0;

describe('findingV0Schema', () => {
  it('validates the minimal example finding', () => {
    const result = validateFinding(minimalFinding);

    expect(result).toEqual({
      success: true,
      data: minimalFinding,
    });
  });

  it('validates the rich example finding', () => {
    const result = validateFinding(richFinding);

    expect(result).toEqual({
      success: true,
      data: richFinding,
    });
  });

  it('narrows with isFinding()', () => {
    const candidate: unknown = minimalFinding;

    if (!isFinding(candidate)) {
      throw new Error('Expected minimal example finding to validate.');
    }

    expect(candidate.schemaVersion).toBe(FINDING_V0_SCHEMA_VERSION);
  });

  it('allows assertValidFinding() to pass for valid input', () => {
    expect(() => {
      assertValidFinding(richFinding);
    }).not.toThrow();
  });

  it('keeps the Zod schema aligned with the helper result', () => {
    expect(findingV0Schema.parse(minimalFinding)).toEqual(minimalFinding);
  });

  it('rejects missing required top-level fields', () => {
    const result = validateFinding({
      ...minimalFinding,
      title: undefined,
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/title',
          code: 'invalid_type',
        }),
      ]),
    });
  });

  it('rejects missing nested required fields', () => {
    const finding = {
      ...minimalFinding,
      rule: {
        ...minimalFinding.rule,
        id: undefined,
      },
    };

    const result = validateFinding(finding);

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/rule/id',
          code: 'invalid_type',
        }),
      ]),
    });
  });

  it('accepts critical severity and numeric confidence', () => {
    const result = validateFinding({
      ...minimalFinding,
      category: 'security.injection',
      severity: 'critical',
      confidence: 0.95,
    });

    expect(result).toEqual({
      success: true,
      data: expect.objectContaining({
        category: 'security.injection',
        severity: 'critical',
        confidence: 0.95,
      }),
    });
  });

  it('rejects invalid category values', () => {
    const result = validateFinding({
      ...minimalFinding,
      category: 'Security Injection',
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/category',
          code: 'invalid_string',
        }),
      ]),
    });
  });

  it('rejects empty evidence arrays', () => {
    const result = validateFinding(
      require('../../examples/finding-invalid.empty-evidence.json'),
    );

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/evidence',
          code: 'too_small',
        }),
      ]),
    });
  });

  it('rejects unknown top-level fields', () => {
    const result = validateFinding(
      require('../../examples/finding-invalid.unknown-top-level.json'),
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

  it('rejects unknown nested fields', () => {
    const result = validateFinding({
      ...minimalFinding,
      rule: {
        ...minimalFinding.rule,
        extra: true,
      },
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/rule',
          code: 'unrecognized_keys',
          received: 'extra',
        }),
      ]),
    });
  });

  it('rejects invalid UUID values', () => {
    const result = validateFinding({
      ...minimalFinding,
      findingId: 'not-a-uuid',
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/findingId',
          code: 'invalid_string',
          expected: 'uuid',
        }),
      ]),
    });
  });

  it('rejects invalid datetime values', () => {
    const result = validateFinding({
      ...minimalFinding,
      provenance: {
        ...minimalFinding.provenance,
        generatedAt: 'yesterday',
      },
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/provenance/generatedAt',
          code: 'invalid_string',
          expected: 'datetime',
        }),
      ]),
    });
  });

  it('rejects fingerprint values without the sha256: prefix', () => {
    const result = validateFinding({
      ...minimalFinding,
      fingerprints: {
        ...minimalFinding.fingerprints,
        primary: 'abcdef',
      },
    });

    expect(result.success).toBe(false);
    expect(result).toEqual({
      success: false,
      issues: expect.arrayContaining([
        expect.objectContaining({
          path: '/fingerprints/primary',
          code: 'invalid_string',
        }),
      ]),
    });
  });
});
