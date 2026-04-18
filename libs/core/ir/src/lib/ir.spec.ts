import {
  loadRuleText,
  validateLoadedRuleDocument,
} from '@critiq/core-rules-dsl';

import { normalizeRuleDocument } from './ir';

function normalize(text: string) {
  const loaded = loadRuleText(text, 'file:///rules/example.yaml');

  if (!loaded.success) {
    throw new Error(`Expected load success: ${JSON.stringify(loaded.diagnostics)}`);
  }

  const validated = validateLoadedRuleDocument(loaded.data);

  if (!validated.success) {
    throw new Error(
      `Expected validation success: ${JSON.stringify(validated.diagnostics)}`,
    );
  }

  return normalizeRuleDocument(validated.data);
}

describe('normalizeRuleDocument', () => {
  it('normalizes aliases, tags, globs, and defaults deterministically', () => {
    const result = normalize(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log',
        '  summary: Use the logger',
        '  tags:',
        '    - maintainability',
        '    - logging',
        '    - logging',
        'scope:',
        '  languages:',
        '    - js',
        '    - ts',
        '  paths:',
        '    include:',
        '      - " src/** "',
        '      - src/**',
        '    exclude:',
        '      - "**/*.test.*"',
        '      - " "**/*.test.*""',
        'match:',
        '  node:',
        '    kind: CallExpression',
        '    bind: call',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '    tags:',
        '      - logging',
        '      - logging',
        '  message:',
        '    title: Avoid console.log',
        '    summary: Found `${captures.call.text}` in `${file.path}`.',
      ].join('\n').replace('" "**/*.test.*""', '"**/*.test.*"'),
    );

    expect(result.rule).toEqual({
      apiVersion: 'critiq.dev/v1alpha1',
      kind: 'Rule',
      ruleId: 'ts.logging.no-console-log',
      title: 'Avoid console.log',
      summary: 'Use the logger',
      rationale: undefined,
      status: undefined,
      stability: undefined,
      appliesTo: undefined,
      tags: ['logging', 'maintainability'],
      scope: {
        languages: ['javascript', 'typescript'],
        includeGlobs: ['src/**'],
        excludeGlobs: ['**/*.test.*'],
        changedLinesOnly: false,
      },
      predicate: {
        type: 'node',
        kind: 'CallExpression',
        bind: 'call',
        where: [],
      },
      emit: {
        finding: {
          category: 'maintainability',
          severity: 'low',
          confidence: 'high',
          tags: ['logging'],
        },
        message: {
          title: {
            raw: 'Avoid console.log',
          },
          summary: {
            raw: 'Found `${captures.call.text}` in `${file.path}`.',
          },
          detail: undefined,
        },
        remediation: undefined,
      },
      ruleHash: result.ruleHash,
    });
    expect(result.debug.uri).toBe('file:///rules/example.yaml');
  });

  it('is idempotent for already normalized semantic content', () => {
    const first = normalize(
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
        '  all:',
        '    - node:',
        '        kind: CallExpression',
        '        bind: call',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Avoid console.log',
        '    summary: Found `${captures.call.text}`',
      ].join('\n'),
    );
    const second = normalize(
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
        '  all:',
        '    - node:',
        '        kind: CallExpression',
        '        bind: call',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Avoid console.log',
        '    summary: Found `${captures.call.text}`',
      ].join('\n'),
    );

    expect(first.rule).toEqual(second.rule);
    expect(first.ruleHash).toBe(second.ruleHash);
  });

  it('produces the same hash for equivalent authored inputs', () => {
    const first = normalize(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log',
        '  summary: Use the logger',
        '  tags:',
        '    - logging',
        '    - maintainability',
        'scope:',
        '  languages:',
        '    - ts',
        '    - js',
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
        '    summary: Use logger',
      ].join('\n'),
    );
    const second = normalize(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log',
        '  summary: Use the logger',
        '  tags:',
        '    - maintainability',
        '    - logging',
        'scope:',
        '  languages:',
        '    - javascript',
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
        '    summary: Use logger',
      ].join('\n'),
    );

    expect(first.ruleHash).toBe(second.ruleHash);
  });

  it('preserves OSS taxonomy metadata and numeric confidence', () => {
    const result = normalize(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.security.no-request-path-file-read',
        '  title: Path traversal via user input',
        '  summary: File reads must not use request-controlled paths directly.',
        '  stability: stable',
        '  appliesTo: block',
        'scope:',
        '  languages:',
        '    - all',
        'match:',
        '  node:',
        '    kind: CallExpression',
        '    bind: readCall',
        'emit:',
        '  finding:',
        '    category: security.filesystem',
        '    severity: high',
        '    confidence: 0.85',
        '  message:',
        '    title: Avoid request-controlled file reads',
        '    summary: Review `${captures.readCall.text}`.',
      ].join('\n'),
    );

    expect(result.rule).toMatchObject({
      ruleId: 'ts.security.no-request-path-file-read',
      stability: 'stable',
      appliesTo: 'block',
      scope: {
        languages: ['all'],
      },
      emit: {
        finding: {
          category: 'security.filesystem',
          severity: 'high',
          confidence: 0.85,
        },
      },
    });
  });

  it('normalizes fact-backed predicates deterministically', () => {
    const result = normalize(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.quality.swallowed-error',
        '  title: Errors swallowed silently',
        '  summary: Catch blocks should log or propagate failures.',
        '  appliesTo: block',
        'scope:',
        '  languages:',
        '    - javascript',
        '    - typescript',
        'match:',
        '  fact:',
        '    kind: error-handling.swallowed-error',
        '    bind: issue',
        '    where:',
        '      - path: appliesTo',
        '        equals: block',
        'emit:',
        '  finding:',
        '    category: quality.error-handling',
        '    severity: medium',
        '    confidence: 0.95',
        '  message:',
        '    title: Avoid swallowed errors',
        '    summary: Review `${captures.issue.text}`.',
      ].join('\n'),
    );

    expect(result.rule).toMatchObject({
      appliesTo: 'block',
      scope: {
        languages: ['javascript', 'typescript'],
      },
      predicate: {
        type: 'fact',
        kind: 'error-handling.swallowed-error',
        bind: 'issue',
        where: [
          {
            path: 'appliesTo',
            operator: 'equals',
            value: 'block',
          },
        ],
      },
    });
  });

  it('matches the canonical golden IR for the example rule', () => {
    const result = normalize(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log in production code',
        '  summary: Production code must use the structured logger.',
        '  rationale: Console logging bypasses standard logging controls.',
        '  tags:',
        '    - logging',
        '    - maintainability',
        '  status: experimental',
        'scope:',
        '  languages:',
        '    - typescript',
        '    - javascript',
        '  paths:',
        '    include:',
        '      - src/**',
        '    exclude:',
        '      - "**/*.test.*"',
        '      - "**/fixtures/**"',
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
        '    title: Avoid console.log in production code',
        '    summary: Use the team logger instead of console.log.',
        '    detail: Found `${captures.call.text}` in `${file.path}`.',
        '  remediation:',
        '    summary: Replace this call with `logger.info` or `logger.debug`.',
      ].join('\n'),
    );

    expect(result.rule).toMatchObject({
      apiVersion: 'critiq.dev/v1alpha1',
      kind: 'Rule',
      ruleId: 'ts.logging.no-console-log',
      title: 'Avoid console.log in production code',
      summary: 'Production code must use the structured logger.',
      rationale: 'Console logging bypasses standard logging controls.',
      status: 'experimental',
      tags: ['logging', 'maintainability'],
      scope: {
        languages: ['javascript', 'typescript'],
        includeGlobs: ['src/**'],
        excludeGlobs: ['**/*.test.*', '**/fixtures/**'],
        changedLinesOnly: true,
      },
      predicate: {
        type: 'all',
        conditions: [
          {
            type: 'node',
            kind: 'CallExpression',
            bind: 'call',
            where: [
              {
                path: 'callee.object.text',
                operator: 'equals',
                value: 'console',
              },
              {
                path: 'callee.property.text',
                operator: 'equals',
                value: 'log',
              },
            ],
          },
          {
            type: 'not',
            condition: {
              type: 'ancestor',
              kind: 'CatchClause',
              where: [],
            },
          },
        ],
      },
      emit: {
        finding: {
          category: 'maintainability',
          severity: 'low',
          confidence: 'high',
          tags: ['logging'],
        },
        message: {
          title: {
            raw: 'Avoid console.log in production code',
          },
          summary: {
            raw: 'Use the team logger instead of console.log.',
          },
          detail: {
            raw: 'Found `${captures.call.text}` in `${file.path}`.',
          },
        },
        remediation: {
          summary: {
            raw: 'Replace this call with `logger.info` or `logger.debug`.',
          },
        },
      },
    });
    expect(result.ruleHash).toMatch(/^[a-f0-9]{64}$/);
  });
});
