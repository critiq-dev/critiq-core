import {
  loadRuleText,
  validateLoadedRuleDocument,
} from '@critiq/core-rules-dsl';
import { normalizeRuleDocument } from '@critiq/core-ir';

import {
  buildFinding,
  evaluateRule,
  evaluateRuleApplicability,
  getAncestorNodes,
  getNodeProperty,
  renderMessageTemplate,
  sortObservedNodes,
  type AnalyzedFile,
  type ObservedNode,
} from './rules-engine';

function createAnalyzedFile(overrides: Partial<AnalyzedFile> = {}): AnalyzedFile {
  const nodes: ObservedNode[] = [
    {
      id: 'call-1',
      kind: 'CallExpression',
      range: {
        startLine: 3,
        startColumn: 1,
        endLine: 3,
        endColumn: 12,
      },
      text: 'console.log',
      parentId: 'function-1',
      props: {
        callee: {
          object: {
            text: 'console',
          },
          property: {
            text: 'log',
          },
        },
      },
    },
    {
      id: 'function-1',
      kind: 'FunctionDeclaration',
      range: {
        startLine: 1,
        startColumn: 1,
        endLine: 5,
        endColumn: 1,
      },
      childrenIds: ['call-1'],
      props: {
        name: {
          text: 'run',
        },
      },
    },
    {
      id: 'catch-call',
      kind: 'CallExpression',
      range: {
        startLine: 8,
        startColumn: 3,
        endLine: 8,
        endColumn: 14,
      },
      text: 'console.log',
      parentId: 'catch-1',
      props: {
        callee: {
          object: {
            text: 'console',
          },
          property: {
            text: 'log',
          },
        },
      },
    },
    {
      id: 'catch-1',
      kind: 'CatchClause',
      range: {
        startLine: 7,
        startColumn: 1,
        endLine: 9,
        endColumn: 1,
      },
      childrenIds: ['catch-call'],
      props: {},
    },
  ];

  return {
    path: 'src/example.ts',
    language: 'typescript',
    text: [
      'function run() {',
      '  logger.info("x");',
      'console.log("x")',
      '}',
      '',
      'try {} catch (error) {',
      '  console.error(error);',
      '  console.log(error)',
      '}',
    ].join('\n'),
    nodes,
    semantics: {
      controlFlow: {
        functions: [],
        blocks: [],
        edges: [],
        facts: [],
      },
    },
    ...overrides,
  };
}

function createFactAnalyzedFile(overrides: Partial<AnalyzedFile> = {}): AnalyzedFile {
  return createAnalyzedFile({
    semantics: {
      controlFlow: {
        functions: [
          {
            id: 'fn-1',
            kind: 'FunctionDeclaration',
            nodeId: 'function-1',
            entryBlockId: 'fn-1:block:entry',
            exitBlockId: 'fn-1:block:exit',
            range: {
              startLine: 1,
              startColumn: 1,
              endLine: 5,
              endColumn: 1,
            },
            text: 'function run() {\n  return value;\n  console.log("x");\n}',
            props: {
              name: 'run',
            },
          },
        ],
        blocks: [],
        edges: [],
        facts: [
          {
            id: 'fact-2',
            kind: 'error-handling.swallowed-error',
            appliesTo: 'block',
            primaryNodeId: 'catch-1',
            functionId: 'fn-1',
            range: {
              startLine: 7,
              startColumn: 1,
              endLine: 9,
              endColumn: 1,
            },
            text: 'catch (error) {\n  console.log(error)\n}',
            props: {
              appliesTo: 'block',
            },
          },
          {
            id: 'fact-1',
            kind: 'control-flow.unreachable-statement',
            appliesTo: 'block',
            primaryNodeId: 'call-1',
            functionId: 'fn-1',
            range: {
              startLine: 3,
              startColumn: 1,
              endLine: 3,
              endColumn: 12,
            },
            text: 'console.log("x")',
            props: {
              reason: 'after-return',
              appliesTo: 'block',
            },
          },
        ],
      },
    },
    ...overrides,
  });
}

function normalizeRule(text: string) {
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

  return normalizeRuleDocument(validated.data).rule;
}

describe('core rules engine pipeline', () => {
  it('performs null-safe property-path access', () => {
    const file = createAnalyzedFile();

    expect(getNodeProperty(file.nodes[0], 'callee.object.text')).toBe('console');
    expect(getNodeProperty(file.nodes[0], 'callee.arguments.0.text')).toBeUndefined();
  });

  it('returns deterministic ancestor traversal', () => {
    const file = createAnalyzedFile();

    expect(getAncestorNodes(file, file.nodes[0]).map((node) => node.id)).toEqual([
      'function-1',
    ]);
  });

  it('sorts observed nodes deterministically', () => {
    const file = createAnalyzedFile();

    expect(sortObservedNodes([...file.nodes].reverse()).map((node) => node.id)).toEqual([
      'function-1',
      'call-1',
      'catch-1',
      'catch-call',
    ]);
  });

  it('evaluates applicability for language and path selectors', () => {
    const rule = normalizeRule(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log',
        '  summary: Use logger',
        'scope:',
        '  languages:',
        '    - typescript',
        '  paths:',
        '    include:',
        '      - src/**',
        '    exclude:',
        '      - "**/*.test.ts"',
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

    expect(evaluateRuleApplicability(rule, createAnalyzedFile())).toEqual({
      applicable: true,
    });
    expect(
      evaluateRuleApplicability(
        rule,
        createAnalyzedFile({
          language: 'javascript',
          path: 'src/example.test.ts',
        }),
      ),
    ).toEqual({
      applicable: false,
      reason: 'language-mismatch',
    });
    expect(
      evaluateRuleApplicability(
        rule,
        createAnalyzedFile({
          language: 'typescript',
          path: 'fixtures/example.ts',
        }),
      ),
    ).toEqual({
      applicable: false,
      reason: 'path-not-included',
    });
  });

  it('treats all as a wildcard language selector', () => {
    const rule = normalizeRule(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.security.no-dynamic-execution',
        '  title: Avoid eval',
        '  summary: Dynamic execution is dangerous.',
        'scope:',
        '  languages:',
        '    - all',
        'match:',
        '  node:',
        '    kind: CallExpression',
        'emit:',
        '  finding:',
        '    category: security.execution',
        '    severity: high',
        '    confidence: 0.95',
        '  message:',
        '    title: Avoid eval',
        '    summary: Avoid dynamic execution.',
      ].join('\n'),
    );

    expect(
      evaluateRuleApplicability(
        rule,
        createAnalyzedFile({
          language: 'javascript',
        }),
      ),
    ).toEqual({
      applicable: true,
    });
  });

  it('uses changedLinesOnly as a file-level fast skip', () => {
    const rule = normalizeRule(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.changed-lines',
        '  title: Avoid console.log',
        '  summary: Use logger',
        'scope:',
        '  languages:',
        '    - typescript',
        '  changedLinesOnly: true',
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

    expect(evaluateRuleApplicability(rule, createAnalyzedFile())).toEqual({
      applicable: false,
      reason: 'no-file-changes',
    });
  });

  it('evaluates all/any/not, captures, operators, and stable ordering', () => {
    const rule = normalizeRule(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log',
        '  summary: Use logger',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  all:',
        '    - node:',
        '        kind: CallExpression',
        '        bind: call',
        '        where:',
        '          - path: callee.object.text',
        '            equals: console',
        '          - path: callee.property.text',
        '            in:',
        '              - log',
        '              - info',
        '          - path: callee.property.text',
        '            matches: "^lo"',
        '          - path: callee.object.text',
        '            exists: true',
        '    - any:',
        '        - node:',
        '            kind: CallExpression',
        '        - ancestor:',
        '            kind: FunctionDeclaration',
        '    - not:',
        '        ancestor:',
        '          kind: CatchClause',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Avoid console.log',
        '    summary: Found `${captures.call.text}` in `${file.path}`.',
      ].join('\n'),
    );
    const matches = evaluateRule(rule, createAnalyzedFile());

    expect(matches).toEqual([
      {
        matchId: 'call-1',
        matchKind: 'node',
        nodeId: 'call-1',
        nodeKind: 'CallExpression',
        range: {
          startLine: 3,
          startColumn: 1,
          endLine: 3,
          endColumn: 12,
        },
        captures: {
          call: {
            nodeId: 'call-1',
            kind: 'CallExpression',
            path: 'src/example.ts',
            text: 'console.log',
            range: {
              startLine: 3,
              startColumn: 1,
              endLine: 3,
              endColumn: 12,
            },
          },
        },
        sortKey: '00000003:00000001:00000003:00000012:call-1',
      },
    ]);
  });

  it('evaluates fact-backed rules with deterministic ordering and captures', () => {
    const rule = normalizeRule(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.correctness.unreachable-statement',
        '  title: Unreachable code after return or throw',
        '  summary: Remove dead code.',
        '  appliesTo: block',
        'scope:',
        '  languages:',
        '    - typescript',
        '    - javascript',
        'match:',
        '  fact:',
        '    kind: control-flow.unreachable-statement',
        '    bind: issue',
        '    where:',
        '      - path: reason',
        '        equals: after-return',
        'emit:',
        '  finding:',
        '    category: correctness.control-flow',
        '    severity: low',
        '    confidence: 0.95',
        '  message:',
        '    title: Remove unreachable code',
        '    summary: Review `${captures.issue.text}`.',
      ].join('\n'),
    );

    expect(evaluateRule(rule, createFactAnalyzedFile())).toEqual([
      {
        matchId: 'fact-1',
        matchKind: 'fact',
        nodeId: 'call-1',
        factId: 'fact-1',
        nodeKind: 'control-flow.unreachable-statement',
        range: {
          startLine: 3,
          startColumn: 1,
          endLine: 3,
          endColumn: 12,
        },
        captures: {
          issue: {
            nodeId: 'call-1',
            factId: 'fact-1',
            kind: 'control-flow.unreachable-statement',
            path: 'src/example.ts',
            text: 'console.log("x")',
            range: {
              startLine: 3,
              startColumn: 1,
              endLine: 3,
              endColumn: 12,
            },
          },
        },
        sortKey: '00000003:00000001:00000003:00000012:fact-1',
      },
    ]);
  });

  it('post-filters matches by changed range intersections', () => {
    const rule = normalizeRule(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.changed-match',
        '  title: Avoid console.log',
        '  summary: Use logger',
        'scope:',
        '  languages:',
        '    - typescript',
        '  changedLinesOnly: true',
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

    expect(
      evaluateRule(
        rule,
        createAnalyzedFile({
          changedRanges: [
            {
              startLine: 3,
              startColumn: 1,
              endLine: 3,
              endColumn: 20,
            },
          ],
        }),
      ).map((match) => match.nodeId),
    ).toEqual(['call-1']);
    expect(
      evaluateRule(
        rule,
        createAnalyzedFile({
          changedRanges: [
            {
              startLine: 1,
              startColumn: 1,
              endLine: 1,
              endColumn: 5,
            },
          ],
        }),
      ),
    ).toEqual([]);
  });

  it('post-filters fact matches by changed range intersections', () => {
    const rule = normalizeRule(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.correctness.unreachable-statement.changed',
        '  title: Remove unreachable code',
        '  summary: Remove dead code.',
        '  appliesTo: block',
        'scope:',
        '  languages:',
        '    - typescript',
        '  changedLinesOnly: true',
        'match:',
        '  fact:',
        '    kind: control-flow.unreachable-statement',
        'emit:',
        '  finding:',
        '    category: correctness.control-flow',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Remove unreachable code',
        '    summary: Remove dead code.',
      ].join('\n'),
    );

    expect(
      evaluateRule(
        rule,
        createFactAnalyzedFile({
          changedRanges: [
            {
              startLine: 3,
              startColumn: 1,
              endLine: 3,
              endColumn: 20,
            },
          ],
        }),
      ).map((match) => match.matchId),
    ).toEqual(['fact-1']);
    expect(
      evaluateRule(
        rule,
        createFactAnalyzedFile({
          changedRanges: [
            {
              startLine: 1,
              startColumn: 1,
              endLine: 1,
              endColumn: 5,
            },
          ],
        }),
      ),
    ).toEqual([]);
  });

  it('renders templates and reports unknown variables cleanly', () => {
    const rule = normalizeRule(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.templates',
        '  title: Avoid console.log',
        '  summary: Use logger',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        '    bind: call',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Avoid `${captures.call.kind}`',
        '    summary: Found `${captures.call.text}` in `${file.path}` for `${rule.title}`.',
      ].join('\n'),
    );
    const [match] = evaluateRule(rule, createAnalyzedFile());

    expect(
      renderMessageTemplate(
        rule.emit.message.summary.raw,
        rule,
        createAnalyzedFile(),
        match,
      ),
    ).toEqual({
      success: true,
      text: 'Found `console.log` in `src/example.ts` for `Avoid console.log`.',
    });
    expect(
      renderMessageTemplate(
        'Found `${captures.call.value}`',
        rule,
        createAnalyzedFile(),
        match,
      ),
    ).toEqual({
      success: false,
      issues: [
        {
          code: 'unknown-variable',
          message: 'Template variable `${captures.call.value}` is not supported.',
          variable: 'captures.call.value',
        },
      ],
    });
  });

  it('builds validated findings with stable fingerprints', () => {
    const rule = normalizeRule(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log',
        '  summary: Use logger',
        'scope:',
        '  languages:',
        '    - typescript',
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
        '  message:',
        '    title: Avoid console.log',
        '    summary: Found `${captures.call.text}` in `${file.path}`.',
        '    detail: Rule `${rule.id}` triggered.',
        '  remediation:',
        '    summary: Replace with logger.info',
      ].join('\n'),
    );
    const analyzedFile = createAnalyzedFile();
    const [match] = evaluateRule(rule, analyzedFile);
    const first = buildFinding(rule, analyzedFile, match, {
      generatedAt: '2026-04-07T10:00:00.000Z',
      engineKind: 'critiq-reviewer',
      engineVersion: '0.0.1',
    });
    const second = buildFinding(rule, analyzedFile, match, {
      generatedAt: '2026-04-07T10:00:00.000Z',
      engineKind: 'critiq-reviewer',
      engineVersion: '0.0.1',
    });

    expect(first.success).toBe(true);
    expect(second.success).toBe(true);

    if (!first.success || !second.success) {
      throw new Error('Expected finding build success.');
    }

    expect(first.finding.fingerprints).toEqual(second.finding.fingerprints);
    expect(first.finding.evidence[0]).toEqual(
      expect.objectContaining({
        kind: 'match-node',
        label: 'Matched CallExpression',
        path: 'src/example.ts',
      }),
    );
    expect(first.finding).toEqual(
      expect.objectContaining({
        schemaVersion: 'finding/v0',
        rule: expect.objectContaining({
          id: 'ts.logging.no-console-log',
        }),
        title: 'Avoid console.log',
        summary: 'Found `console.log` in `src/example.ts`.',
      }),
    );
  });

  it('builds validated findings from fact-backed matches', () => {
    const rule = normalizeRule(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.quality.swallowed-error',
        '  title: Errors swallowed silently',
        '  summary: Catch blocks must log or propagate failures.',
        '  appliesTo: block',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  fact:',
        '    kind: error-handling.swallowed-error',
        '    bind: issue',
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
    const analyzedFile = createFactAnalyzedFile();
    const [match] = evaluateRule(rule, analyzedFile);
    const result = buildFinding(rule, analyzedFile, match, {
      generatedAt: '2026-04-13T10:00:00.000Z',
    });

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected fact-backed finding build success.');
    }

    expect(result.finding.evidence[0]).toEqual(
      expect.objectContaining({
        label: 'Matched error-handling.swallowed-error',
        excerpt: 'catch (error) {\n  console.log(error)\n}',
      }),
    );
    expect(result.finding.locations.primary).toEqual(
      expect.objectContaining({
        startLine: 7,
        startColumn: 1,
      }),
    );
  });
});
