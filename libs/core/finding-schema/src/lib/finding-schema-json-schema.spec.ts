import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { findingV0JsonSchema, type FindingV0, validateFinding } from '../index';

const minimalFinding =
  require('../../examples/finding-minimal.valid.json') as FindingV0;
const richFinding =
  require('../../examples/finding-rich.valid.json') as FindingV0;
const invalidUnknownTopLevel = require('../../examples/finding-invalid.unknown-top-level.json');

describe('findingV0JsonSchema', () => {
  it('matches the schema generated from the Zod source of truth', () => {
    const generatorScriptPath = resolve(
      __dirname,
      '../../scripts/generate-finding-v0-schema.cjs',
    );
    const tempSchemaPath = resolve(
      __dirname,
      '../../tmp/finding-v0.generated.schema.json',
    );

    execFileSync('node', [generatorScriptPath, tempSchemaPath]);

    const regeneratedSchema = JSON.parse(
      readFileSync(tempSchemaPath, 'utf8'),
    ) as Record<string, unknown>;

    expect(findingV0JsonSchema).toEqual(regeneratedSchema);
  });

  it('validates the checked-in valid examples with Ajv', () => {
    const ajv = new Ajv({
      allErrors: true,
      strict: false,
    });

    addFormats(ajv);

    const validate = ajv.compile(findingV0JsonSchema);

    expect(validate(minimalFinding)).toBe(true);
    expect(validate.errors).toBeNull();
    expect(validate(richFinding)).toBe(true);
    expect(validate.errors).toBeNull();
  });

  it('rejects the invalid top-level fixture through both validators', () => {
    const ajv = new Ajv({
      allErrors: true,
      strict: false,
    });

    addFormats(ajv);

    const validate = ajv.compile(findingV0JsonSchema);

    expect(validate(invalidUnknownTopLevel)).toBe(false);
    expect(validate.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          keyword: 'additionalProperties',
        }),
      ]),
    );

    expect(validateFinding(invalidUnknownTopLevel).success).toBe(false);
  });
});
