import {
  DIAGNOSTIC_CODE_YAML_MAPPING_DUPLICATE_KEY,
  DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
} from '@critiq/core-diagnostics';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadRuleFile, loadRuleText } from '../index';

describe('rule YAML loading', () => {
  it('loads a minimal valid rule with source mappings', () => {
    const result = loadRuleText(
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
        '    title: Avoid console.log',
        '    summary: Use logger.info instead',
      ].join('\n'),
      'file:///rules/minimal.yaml',
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected valid rule YAML to load successfully.');
    }

    expect(result.data.document).toEqual({
      apiVersion: 'critiq.dev/v1alpha1',
      kind: 'Rule',
      metadata: {
        id: 'ts.logging.no-console-log',
        title: 'Avoid console.log',
        summary: 'Use the logger',
      },
      scope: {
        languages: ['typescript'],
      },
      match: {
        node: {
          kind: 'CallExpression',
        },
      },
      emit: {
        finding: {
          category: 'maintainability',
          severity: 'low',
          confidence: 'high',
        },
        message: {
          title: 'Avoid console.log',
          summary: 'Use logger.info instead',
        },
      },
    });
    expect(result.data.sourceMap['/']).toBeDefined();
    expect(result.data.sourceMap['/metadata/id']).toEqual({
      keySpan: {
        uri: 'file:///rules/minimal.yaml',
        start: {
          line: 4,
          column: 3,
        },
        end: {
          line: 4,
          column: 4,
        },
      },
      valueSpan: {
        uri: 'file:///rules/minimal.yaml',
        start: {
          line: 4,
          column: 7,
        },
        end: {
          line: 4,
          column: 31,
        },
      },
    });
    expect(result.data.sourceMap['/match'].valueSpan.start).toEqual({
      line: 11,
      column: 3,
    });
    expect(result.data.sourceMap['/emit/message/title'].valueSpan.start).toEqual(
      {
        line: 19,
        column: 12,
      },
    );
  });

  it('loads a full valid rule example', () => {
    const result = loadRuleText(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log',
        '  summary: Use the logger',
        '  rationale: Console logging bypasses controls',
        '  tags:',
        '    - logging',
        '    - maintainability',
        'scope:',
        '  languages:',
        '    - typescript',
        '    - javascript',
        '  paths:',
        '    include:',
        '      - src/**',
        '    exclude:',
        '      - "**/*.test.*"',
        '  changedLinesOnly: true',
        'match:',
        '  all:',
        '    - node:',
        '        kind: CallExpression',
        '        bind: call',
        '        where:',
        '          - path: callee.object.text',
        '            equals: console',
        '          - path: callee.property.text',
        '            equals: log',
        '    - not:',
        '        ancestor:',
        '          kind: CatchClause',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '    tags:',
        '      - logging',
        '  message:',
        '    title: Avoid console.log',
        '    summary: Use the team logger',
        '    detail: Found "${captures.call.text}"',
        '  remediation:',
        '    summary: Replace console.log',
      ].join('\n'),
      'file:///rules/full.yaml',
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected full rule YAML to load successfully.');
    }

    expect(result.data.sourceMap['/scope/languages/1'].valueSpan.start).toEqual({
      line: 14,
      column: 7,
    });
    expect(result.data.sourceMap['/match/all/0/node/where/1/equals'].valueSpan.start)
      .toEqual({
        line: 30,
        column: 21,
      });
  });

  it('returns syntax diagnostics with exact location', () => {
    const result = loadRuleText(
      'metadata:\n  id: [unterminated\n',
      'file:///rules/syntax.yaml',
    );

    expect(result.success).toBe(false);

    if (result.success) {
      throw new Error('Expected syntax failure.');
    }

    expect(result.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
          sourceSpan: expect.objectContaining({
            uri: 'file:///rules/syntax.yaml',
            start: expect.objectContaining({
              line: 3,
            }),
          }),
        }),
      ]),
    );
  });

  it('returns duplicate-key diagnostics with exact location', () => {
    const result = loadRuleText(
      ['metadata:', '  id: one', '  id: two'].join('\n'),
      'file:///rules/duplicate.yaml',
    );

    expect(result.success).toBe(false);

    if (result.success) {
      throw new Error('Expected duplicate-key failure.');
    }

    expect(result.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: DIAGNOSTIC_CODE_YAML_MAPPING_DUPLICATE_KEY,
          sourceSpan: expect.objectContaining({
            uri: 'file:///rules/duplicate.yaml',
            start: expect.objectContaining({
              line: 3,
              column: 3,
            }),
          }),
        }),
      ]),
    );
  });

  it('rejects multi-document YAML as a loader error', () => {
    const result = loadRuleText(
      ['metadata:', '  id: first', '---', 'metadata:', '  id: second'].join('\n'),
      'file:///rules/multi.yaml',
    );

    expect(result.success).toBe(false);

    if (result.success) {
      throw new Error('Expected multi-document failure.');
    }

    expect(result.diagnostics).toEqual([
      expect.objectContaining({
        code: DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
        message: 'Multiple YAML documents are not supported in v0.',
      }),
    ]);
  });

  it('loads a rule file by delegating to the text loader', () => {
    const tempDirectory = mkdtempSync(join(tmpdir(), 'rule-loader-'));
    const filePath = join(tempDirectory, 'rule.yaml');

    writeFileSync(
      filePath,
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
        '    title: Avoid console.log',
        '    summary: Use logger.info instead',
      ].join('\n'),
      'utf8',
    );

    const result = loadRuleFile(filePath);

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected file load to succeed.');
    }

    expect(result.data.uri).toBe(pathToFileURL(filePath).href);
    expect(result.data.sourceMap['/metadata/id']).toBeDefined();
  });
});
