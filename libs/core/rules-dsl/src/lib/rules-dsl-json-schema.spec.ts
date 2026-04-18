import Ajv from 'ajv';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import {
  ruleDocumentV0Alpha1JsonSchema,
  type RuleDocumentV0Alpha1,
  validateRuleDocument,
} from '../index';

const minimalRule =
  require('../../examples/rule-minimal.valid.json') as RuleDocumentV0Alpha1;
const fullRule =
  require('../../examples/rule-full.valid.json') as RuleDocumentV0Alpha1;
const invalidTopLevel = require('../../examples/rule-invalid.extra-top-level.json');

describe('ruleDocumentV0Alpha1JsonSchema', () => {
  it('matches the schema generated from the Zod source of truth', () => {
    const generatorScriptPath = resolve(
      __dirname,
      '../../scripts/generate-rule-document-v0alpha1-schema.cjs',
    );
    const tempDirectory = mkdtempSync(join(tmpdir(), 'rules-dsl-schema-'));
    const tempSchemaPath = join(
      tempDirectory,
      'rule-document-v0alpha1.generated.schema.json',
    );

    execFileSync('node', [generatorScriptPath, tempSchemaPath]);

    const regeneratedSchema = JSON.parse(
      readFileSync(tempSchemaPath, 'utf8'),
    ) as Record<string, unknown>;

    expect(ruleDocumentV0Alpha1JsonSchema).toEqual(regeneratedSchema);
  });

  it('validates the checked-in valid examples with Ajv', () => {
    const ajv = new Ajv({
      allErrors: true,
      strict: false,
    });

    const validate = ajv.compile(ruleDocumentV0Alpha1JsonSchema);

    expect(validate(minimalRule)).toBe(true);
    expect(validate.errors).toBeNull();
    expect(validate(fullRule)).toBe(true);
    expect(validate.errors).toBeNull();
  });

  it('rejects invalid examples through both validators', () => {
    const ajv = new Ajv({
      allErrors: true,
      strict: false,
    });

    const validate = ajv.compile(ruleDocumentV0Alpha1JsonSchema);

    expect(validate(invalidTopLevel)).toBe(false);
    expect(validate.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          keyword: 'additionalProperties',
        }),
      ]),
    );
    expect(validateRuleDocument(invalidTopLevel).success).toBe(false);
  });
});
