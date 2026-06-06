import {
  CFN_LINT_FACT_KIND,
  collectCfnLintFacts,
} from './collect-cfn-lint-facts.util';

describe('collectCfnLintFacts', () => {
  it('emits cfn.lint.finding facts with external rule metadata', () => {
    const text = [
      'AWSTemplateFormatVersion: 2010-09-09',
      'Resources:',
      '  Bucket:',
      '    Type: AWS::S3::Bucket',
      '    Properties:',
      '      BucketName: !Ref MissingParam',
    ].join('\n');

    const facts = collectCfnLintFacts(text, [
      {
        ruleId: 'E1020',
        level: 'Error',
        message: 'Ref MissingParam not found',
        line: 7,
        column: 19,
        endLine: 7,
        endColumn: 30,
      },
    ]);

    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe(CFN_LINT_FACT_KIND);
    expect(facts[0]?.props).toEqual({
      ruleId: 'E1020',
      level: 'Error',
      message: 'Ref MissingParam not found',
      line: 7,
      column: 19,
    });
    expect(facts[0]?.range).toEqual({
      startLine: 7,
      startColumn: 19,
      endLine: 7,
      endColumn: 30,
    });
  });
});
