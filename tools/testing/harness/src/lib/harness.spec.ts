import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  formatRuleSpecRunForTerminal,
  runRuleSpec,
  validateRuleSpec,
  workspaceHarnessPackageName,
} from '../index';
import {
  readWorkspaceArchitecture,
  validateWorkspaceArchitecture,
  type WorkspaceArchitectureSnapshot,
} from './workspace-architecture';

function createTempWorkspace(): string {
  return mkdtempSync(join(tmpdir(), 'critiq-harness-'));
}

function writeWorkspaceFile(
  rootDirectory: string,
  relativePath: string,
  content: string,
): void {
  const absolutePath = join(rootDirectory, relativePath);
  mkdirSync(dirname(absolutePath), { recursive: true });
  writeFileSync(absolutePath, content, 'utf8');
}

const consoleLogRule = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: Rule',
  'metadata:',
  '  id: ts.logging.no-console-log',
  '  title: Avoid console.log',
  '  summary: Use the project logger.',
  'scope:',
  '  languages:',
  '    - typescript',
  'match:',
  '  node:',
  '    kind: CallExpression',
  '    bind: call',
  '    where:',
  '      - path: callee.object.text',
  '        equals: console',
  '      - path: callee.property.text',
  '        equals: log',
  'emit:',
  '  finding:',
  '    category: maintainability',
  '    severity: low',
  '    confidence: high',
  '  message:',
  '    title: Avoid `${captures.call.text}`',
  '    summary: Replace `${captures.call.text}` with the logger',
].join('\n');

const matchingSource = 'console.log("hello");\n';

const passingSpec = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: RuleSpec',
  'rulePath: ./no-console.rule.yaml',
  'fixtures:',
  '  - name: console log is flagged',
  '    sourcePath: ../fixtures/invalid.ts',
  '    expect:',
  '      findingCount: 1',
  '      allRuleIds:',
  '        - ts.logging.no-console-log',
  '      allSeverities:',
  '        - low',
  '      titleContains:',
  '        - Avoid',
  '      summaryContains:',
  '        - logger',
  '      primaryLocation:',
  '        line: 1',
  '        column: 1',
].join('\n');

const failingSpec = passingSpec.replace('findingCount: 1', 'findingCount: 0');
const factRule = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: Rule',
  'metadata:',
  '  id: ts.correctness.unreachable-statement',
  '  title: Remove unreachable statement',
  '  summary: Remove dead code after terminal exits.',
  '  appliesTo: block',
  'scope:',
  '  languages:',
  '    - typescript',
  'match:',
  '  fact:',
  '    kind: control-flow.unreachable-statement',
  '    bind: issue',
  'emit:',
  '  finding:',
  '    category: correctness.control-flow',
  '    severity: low',
  '    confidence: high',
  '  message:',
  '    title: Remove unreachable statement',
  '    summary: Review `${captures.issue.text}`',
].join('\n');

describe('workspaceHarnessPackageName', () => {
  it('returns the expected package import path', () => {
    expect(workspaceHarnessPackageName()).toBe('@critiq/testing-harness');
  });
});

describe('rule spec validation', () => {
  it('rejects fixtures that omit both sourcePath and observationPath', () => {
    expect(
      validateRuleSpec({
        apiVersion: 'critiq.dev/v1alpha1',
        kind: 'RuleSpec',
        rulePath: './rules/example.rule.yaml',
        fixtures: [
          {
            name: 'broken',
            expect: {
              findingCount: 0,
            },
          },
        ],
      }),
    ).toEqual({
      success: false,
      issues: [
        expect.objectContaining({
          path: '/fixtures/0/sourcePath',
        }),
      ],
    });
  });
});

describe('runRuleSpec', () => {
  let tempDirectory: string;

  beforeEach(() => {
    tempDirectory = createTempWorkspace();
    writeWorkspaceFile(tempDirectory, 'rules/no-console.rule.yaml', consoleLogRule);
    writeWorkspaceFile(tempDirectory, 'fixtures/invalid.ts', matchingSource);
  });

  afterEach(() => {
    rmSync(tempDirectory, { recursive: true, force: true });
  });

  it('executes a valid rule spec against a real source fixture', () => {
    writeWorkspaceFile(tempDirectory, 'rules/no-console.spec.yaml', passingSpec);

    const result = runRuleSpec(join(tempDirectory, 'rules/no-console.spec.yaml'));

    expect(result.success).toBe(true);
    expect(result.diagnostics).toEqual([]);
    expect(result.fixtureResults).toHaveLength(1);
    expect(result.fixtureResults[0]).toEqual(
      expect.objectContaining({
        name: 'console log is flagged',
        sourceKind: 'source',
        success: true,
        emittedFindings: [
          expect.objectContaining({
            title: 'Avoid `console.log("hello")`',
            ruleId: 'ts.logging.no-console-log',
            severity: 'low',
            primaryLocation: {
              line: 1,
              column: 1,
            },
          }),
        ],
      }),
    );
  });

  it('renders stable output for a failing spec', () => {
    writeWorkspaceFile(tempDirectory, 'rules/no-console.spec.yaml', failingSpec);

    const result = runRuleSpec(join(tempDirectory, 'rules/no-console.spec.yaml'));
    const output = formatRuleSpecRunForTerminal(result).replace(
      new RegExp(tempDirectory.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'),
      '<TMP>',
    );

    expect(result.success).toBe(false);
    expect(output).toMatchInlineSnapshot(`
"RuleSpec: <TMP>/rules/no-console.spec.yaml
Rule: <TMP>/rules/no-console.rule.yaml

FAIL console log is flagged (source)
Fixture: <TMP>/fixtures/invalid.ts
Assertion failures:
- findingCount: Expected findingCount to match exactly.
  expected: 0
  received: 1

Success: false"
`);
  });

  it('accepts observation fixtures with semantic control-flow data', () => {
    writeWorkspaceFile(
      tempDirectory,
      'rules/unreachable.rule.yaml',
      factRule,
    );
    writeWorkspaceFile(
      tempDirectory,
      'fixtures/unreachable.observation.json',
      JSON.stringify(
        {
          path: 'src/example.ts',
          language: 'typescript',
          text: 'function run() {\n  return 1;\n  const dead = 2;\n}\n',
          nodes: [
            {
              id: 'return-1',
              kind: 'ReturnStatement',
              range: {
                startLine: 2,
                startColumn: 3,
                endLine: 2,
                endColumn: 11,
              },
              text: 'return 1;',
              props: {},
            },
            {
              id: 'dead-1',
              kind: 'VariableDeclaration',
              range: {
                startLine: 3,
                startColumn: 3,
                endLine: 3,
                endColumn: 18,
              },
              text: 'const dead = 2;',
              props: {},
            },
          ],
          semantics: {
            controlFlow: {
              functions: [
                {
                  id: 'fn-1',
                  kind: 'FunctionDeclaration',
                  nodeId: 'return-1',
                  entryBlockId: 'fn-1:block:entry',
                  exitBlockId: 'fn-1:block:exit',
                  range: {
                    startLine: 1,
                    startColumn: 1,
                    endLine: 4,
                    endColumn: 1,
                  },
                  text: 'function run() {\n  return 1;\n  const dead = 2;\n}',
                  props: {},
                },
              ],
              blocks: [],
              edges: [],
              facts: [
                {
                  id: 'fact-1',
                  kind: 'control-flow.unreachable-statement',
                  appliesTo: 'block',
                  primaryNodeId: 'dead-1',
                  functionId: 'fn-1',
                  range: {
                    startLine: 3,
                    startColumn: 3,
                    endLine: 3,
                    endColumn: 18,
                  },
                  text: 'const dead = 2;',
                  props: {
                    reason: 'after-return',
                  },
                },
              ],
            },
          },
        },
        null,
        2,
      ),
    );
    writeWorkspaceFile(
      tempDirectory,
      'rules/unreachable.spec.yaml',
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: RuleSpec',
        'rulePath: ./unreachable.rule.yaml',
        'fixtures:',
        '  - name: observation fixture hits fact-backed rule',
        '    observationPath: ../fixtures/unreachable.observation.json',
        '    expect:',
        '      findingCount: 1',
        '      allRuleIds:',
        '        - ts.correctness.unreachable-statement',
      ].join('\n'),
    );

    const result = runRuleSpec(join(tempDirectory, 'rules/unreachable.spec.yaml'));

    expect(result.success).toBe(true);
    expect(result.fixtureResults[0]).toEqual(
      expect.objectContaining({
        sourceKind: 'observation',
        success: true,
      }),
    );
  });
});

describe('workspace architecture', () => {
  it('matches the required projects, scripts, and module boundaries', async () => {
    const snapshot = await readWorkspaceArchitecture();

    expect(validateWorkspaceArchitecture(snapshot)).toEqual([]);
  });

  it('reports invalid project tags and missing root scripts', () => {
    const invalidSnapshot: WorkspaceArchitectureSnapshot = {
      projects: [
        {
          name: 'cli',
          projectType: 'application',
          root: 'apps/cli',
          tags: ['scope:oss-core', 'type:app'],
        },
        {
          name: 'finding-schema',
          projectType: 'library',
          root: 'libs/core/finding-schema',
          tags: ['scope:oss-core'],
        },
      ],
      rootScripts: {
        lint: 'nx run-many -t lint --all',
      },
      depConstraints: [],
    };

    expect(validateWorkspaceArchitecture(invalidSnapshot)).toEqual(
      expect.arrayContaining([
        'Missing root script: build',
        'Project libs/core/finding-schema is missing required tag type:core.',
        'Module boundaries are not configured with the expected dependency matrix.',
      ]),
    );
  });
});
