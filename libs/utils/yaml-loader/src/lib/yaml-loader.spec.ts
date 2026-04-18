import { loadYamlText } from './yaml-loader';

describe('loadYamlText', () => {
  it('parses valid YAML and preserves nested spans', () => {
    const result = loadYamlText(
      [
        'metadata:',
        '  id: ts.logging.no-console-log',
        'match:',
        '  node:',
        '    kind: CallExpression',
        'emit:',
        '  message:',
        '    title: Avoid console.log',
      ].join('\n'),
      'file:///rules/example.yaml',
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected valid YAML to parse successfully.');
    }

    expect(result.data).toEqual({
      metadata: {
        id: 'ts.logging.no-console-log',
      },
      match: {
        node: {
          kind: 'CallExpression',
        },
      },
      emit: {
        message: {
          title: 'Avoid console.log',
        },
      },
    });
    expect(result.sourceMap['/']).toEqual({
      valueSpan: {
        uri: 'file:///rules/example.yaml',
        start: {
          line: 1,
          column: 1,
        },
        end: {
          line: 8,
          column: 28,
        },
      },
    });
    expect(result.sourceMap['/metadata/id']).toEqual({
      keySpan: {
        uri: 'file:///rules/example.yaml',
        start: {
          line: 2,
          column: 3,
        },
        end: {
          line: 2,
          column: 4,
        },
      },
      valueSpan: {
        uri: 'file:///rules/example.yaml',
        start: {
          line: 2,
          column: 7,
        },
        end: {
          line: 2,
          column: 31,
        },
      },
    });
    expect(result.sourceMap['/match'].valueSpan.start).toEqual({
      line: 4,
      column: 3,
    });
    expect(result.sourceMap['/emit/message/title'].valueSpan.start).toEqual({
      line: 8,
      column: 12,
    });
  });

  it('returns syntax issues with exact location', () => {
    const result = loadYamlText('metadata:\n  id: [unterminated\n', 'file:///bad.yaml');

    expect(result.success).toBe(false);

    if (result.success) {
      throw new Error('Expected syntax failure.');
    }

    expect(result.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'syntax',
          sourceSpan: expect.objectContaining({
            uri: 'file:///bad.yaml',
            start: expect.objectContaining({
              line: 3,
            }),
          }),
        }),
      ]),
    );
  });

  it('returns duplicate-key issues with exact location', () => {
    const result = loadYamlText(
      ['metadata:', '  id: first', '  id: second'].join('\n'),
      'file:///duplicate.yaml',
    );

    expect(result.success).toBe(false);

    if (result.success) {
      throw new Error('Expected duplicate key failure.');
    }

    expect(result.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'duplicate-key',
          sourceSpan: expect.objectContaining({
            uri: 'file:///duplicate.yaml',
            start: expect.objectContaining({
              line: 3,
              column: 3,
            }),
          }),
        }),
      ]),
    );
  });

  it('rejects multi-document YAML in v0', () => {
    const result = loadYamlText(
      ['metadata:', '  id: first', '---', 'metadata:', '  id: second'].join('\n'),
      'file:///multi.yaml',
    );

    expect(result.success).toBe(false);

    if (result.success) {
      throw new Error('Expected multi-document failure.');
    }

    expect(result.issues).toEqual([
      expect.objectContaining({
        kind: 'multi-document',
        message: 'Multiple YAML documents are not supported in v0.',
      }),
    ]);
  });
});
