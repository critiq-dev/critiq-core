import {
  isCloudFormationTemplate,
  looksLikeCloudFormationPath,
} from './is-cloudformation-template.util';

describe('isCloudFormationTemplate', () => {
  it('detects AWSTemplateFormatVersion in YAML', () => {
    const text = [
      'AWSTemplateFormatVersion: 2010-09-09',
      'Resources:',
      '  Bucket:',
      '    Type: AWS::S3::Bucket',
    ].join('\n');

    expect(isCloudFormationTemplate('template.yaml', text)).toBe(true);
  });

  it('detects SAM transforms in YAML', () => {
    const text = [
      'Transform: AWS::Serverless',
      'Resources:',
      '  Function:',
      '    Type: AWS::Serverless::Function',
    ].join('\n');

    expect(isCloudFormationTemplate('template.yml', text)).toBe(true);
  });

  it('detects CloudFormation JSON templates', () => {
    const text = JSON.stringify({
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        Bucket: {
          Type: 'AWS::S3::Bucket',
        },
      },
    });

    expect(isCloudFormationTemplate('template.json', text)).toBe(true);
  });

  it('matches template paths under common IaC directories', () => {
    expect(
      looksLikeCloudFormationPath(
        'scenarios/iac/cloudformation/templates/bad-invalid-ref.yaml',
      ),
    ).toBe(true);
    expect(looksLikeCloudFormationPath('.critiq/config.yaml')).toBe(false);
  });

  it('rejects generic JSON files', () => {
    expect(
      isCloudFormationTemplate(
        'package.json',
        JSON.stringify({ name: 'example' }),
      ),
    ).toBe(false);
  });
});
