import {
  analyzeCloudFormationFile,
  cloudformationSourceAdapter,
} from './cloudformation';
import { CFN_LINT_FACT_KIND } from './collect-cfn-lint-facts.util';

describe('analyzeCloudFormationFile', () => {
  const template = [
    'AWSTemplateFormatVersion: 2010-09-09',
    'Parameters:',
    '  UnusedParam:',
    '    Type: String',
    'Resources:',
    '  Bucket:',
    '    Type: AWS::S3::Bucket',
    '    Properties:',
    '      BucketName: !Ref MissingParam',
  ].join('\n');

  it('returns empty facts for non-template JSON', () => {
    const result = analyzeCloudFormationFile(
      'package.json',
      JSON.stringify({ name: 'example' }),
    );

    expect(result.success).toBe(true);

    if (result.success) {
      expect(result.data.semantics?.controlFlow?.facts ?? []).toEqual([]);
    }
  });

  it('maps mocked cfn-lint output into observed facts', () => {
    const mockedStdout = JSON.stringify([
      {
        Filename: 'template.yaml',
        Level: 'Error',
        Message: 'Ref MissingParam not found',
        Rule: {
          Id: 'E1020',
          Description: 'Ref validation of value',
        },
        Location: {
          Start: {
            LineNumber: 9,
            ColumnNumber: 19,
          },
          End: {
            LineNumber: 9,
            ColumnNumber: 30,
          },
        },
      },
      {
        Filename: 'template.yaml',
        Level: 'Informational',
        Message: 'Template size',
        Rule: {
          Id: 'I1002',
          Description: 'Template size limit',
        },
        Location: {
          Start: {
            LineNumber: 1,
            ColumnNumber: 1,
          },
          End: {
            LineNumber: 1,
            ColumnNumber: 1,
          },
        },
      },
    ]);

    const result = analyzeCloudFormationFile('template.yaml', template, {
      runCfnLint: () => ({
        ok: true,
        stdout: mockedStdout,
        stderr: '',
        exitCode: 2,
      }),
    });

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected successful analysis');
    }

    const facts = result.data.semantics?.controlFlow?.facts ?? [];

    expect(facts).toHaveLength(2);
    expect(facts.map((fact) => fact.kind)).toEqual([
      CFN_LINT_FACT_KIND,
      CFN_LINT_FACT_KIND,
    ]);
    expect(facts.map((fact) => fact.props['ruleId'])).toEqual(['I1002', 'E1020']);
    expect(facts.find((fact) => fact.props['ruleId'] === 'E1020')?.props).toMatchObject({
      level: 'Error',
      message: 'Ref MissingParam not found',
      line: 9,
      column: 19,
    });
  });

  it('emits a warning diagnostic when cfn-lint is missing', () => {
    const result = analyzeCloudFormationFile('template.yaml', template, {
      runCfnLint: () => ({
        ok: false,
        stdout: '',
        stderr: '',
        exitCode: -1,
        errorCode: 'ENOENT',
      }),
    });

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected successful analysis');
    }

    expect(result.diagnostics?.[0]?.code).toBe(
      'adapter.cloudformation.cfn-lint-missing',
    );
    expect(result.data.semantics?.controlFlow?.facts ?? []).toEqual([]);
  });
});

describe('cloudformationSourceAdapter', () => {
  it('exposes cloudformation extensions and content detection', () => {
    expect(cloudformationSourceAdapter.packageName).toBe(
      '@critiq/adapter-cloudformation',
    );
    expect(cloudformationSourceAdapter.supportedExtensions).toEqual([
      '.yaml',
      '.yml',
      '.json',
    ]);
    expect(cloudformationSourceAdapter.supportedLanguages).toEqual([
      'cloudformation',
    ]);
    expect(
      cloudformationSourceAdapter.canHandle?.(
        'template.yaml',
        'AWSTemplateFormatVersion: 2010-09-09\nResources: {}',
      ),
    ).toBe(true);
  });
});
