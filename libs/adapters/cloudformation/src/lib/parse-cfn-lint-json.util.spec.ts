import { parseCfnLintJson } from './parse-cfn-lint-json.util';

describe('parseCfnLintJson', () => {
  it('parses cfn-lint JSON matches', () => {
    const stdout = JSON.stringify([
      {
        Filename: 'template.yaml',
        Level: 'Error',
        Message: 'Ref not found',
        Rule: {
          Id: 'E1020',
          Description: 'Ref validation of value',
        },
        Location: {
          Start: {
            LineNumber: 7,
            ColumnNumber: 3,
          },
          End: {
            LineNumber: 7,
            ColumnNumber: 10,
          },
        },
      },
      {
        Filename: 'template.yaml',
        Level: 'Warning',
        Message: 'Parameter not used',
        Rule: {
          Id: 'W2001',
          Description: 'Check if parameters are used',
        },
        Location: {
          Start: {
            LineNumber: 4,
            ColumnNumber: 1,
          },
          End: {
            LineNumber: 4,
            ColumnNumber: 1,
          },
        },
      },
    ]);

    expect(parseCfnLintJson(stdout)).toEqual([
      {
        ruleId: 'E1020',
        level: 'Error',
        message: 'Ref not found',
        line: 7,
        column: 3,
        endLine: 7,
        endColumn: 10,
      },
      {
        ruleId: 'W2001',
        level: 'Warning',
        message: 'Parameter not used',
        line: 4,
        column: 1,
        endLine: 4,
        endColumn: 1,
      },
    ]);
  });

  it('returns an empty list for invalid JSON', () => {
    expect(parseCfnLintJson('not-json')).toEqual([]);
  });
});
