import {
  createDiagnostic,
  formatDiagnosticsForTerminal,
  type Diagnostic,
} from '@critiq/core-diagnostics';
import { normalizeRuleDocument } from '@critiq/core-ir';
import {
  buildFinding,
  evaluateRule,
  type AnalyzedFile,
  type BuildFindingIssue,
  type EvaluationMatch,
  type BuildFindingResult,
} from '@critiq/core-rules-engine';
import {
  loadRuleFile,
  validateLoadedRuleDocument,
} from '@critiq/core-rules-dsl';
import {
  augmentProjectFacts,
  createDefaultSourceAdapterRegistry,
  isTestPath,
  toDisplayPath,
  walkFiles,
  type SourceAdapterRegistry,
} from '@critiq/check-runner';
import { loadYamlText } from '@critiq/util-yaml-loader';
import { readFileSync } from 'node:fs';
import { dirname, extname, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { z } from 'zod';

const observedRangeSchema = z
  .object({
    startLine: z.number().int().positive(),
    startColumn: z.number().int().positive(),
    endLine: z.number().int().positive(),
    endColumn: z.number().int().positive(),
  })
  .strict();

const observedNodeSchema = z
  .object({
    id: z.string().min(1),
    kind: z.string().min(1),
    range: observedRangeSchema,
    text: z.string().optional(),
    parentId: z.string().min(1).optional(),
    childrenIds: z.array(z.string().min(1)).optional(),
    props: z.record(z.unknown()),
  })
  .strict();

const observedFunctionSchema = z
  .object({
    id: z.string().min(1),
    kind: z.string().min(1),
    nodeId: z.string().min(1),
    entryBlockId: z.string().min(1),
    exitBlockId: z.string().min(1),
    range: observedRangeSchema,
    text: z.string().optional(),
    props: z.record(z.unknown()),
  })
  .strict();

const observedBasicBlockSchema = z
  .object({
    id: z.string().min(1),
    functionId: z.string().min(1),
    kind: z.string().min(1),
    range: observedRangeSchema,
    statementNodeIds: z.array(z.string().min(1)),
    props: z.record(z.unknown()),
  })
  .strict();

const observedControlFlowEdgeSchema = z
  .object({
    id: z.string().min(1),
    functionId: z.string().min(1),
    fromBlockId: z.string().min(1),
    toBlockId: z.string().min(1),
    kind: z.string().min(1),
    props: z.record(z.unknown()),
  })
  .strict();

const observedFactSchema = z
  .object({
    id: z.string().min(1),
    kind: z.string().min(1),
    appliesTo: z.enum(['block', 'function', 'file', 'project']),
    primaryNodeId: z.string().min(1).optional(),
    functionId: z.string().min(1).optional(),
    blockId: z.string().min(1).optional(),
    range: observedRangeSchema,
    text: z.string().optional(),
    props: z.record(z.unknown()),
  })
  .strict();

const observedControlFlowSchema = z
  .object({
    functions: z.array(observedFunctionSchema),
    blocks: z.array(observedBasicBlockSchema),
    edges: z.array(observedControlFlowEdgeSchema),
    facts: z.array(observedFactSchema),
  })
  .strict();

const analyzedFileSchema = z
  .object({
    path: z.string().min(1),
    language: z.string().min(1),
    text: z.string(),
    nodes: z.array(observedNodeSchema),
    changedRanges: z.array(observedRangeSchema).optional(),
    semantics: z
      .object({
        controlFlow: observedControlFlowSchema.optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

const ruleSpecFixtureExpectationSchema = z
  .object({
    findingCount: z.number().int().min(0),
    allRuleIds: z.array(z.string().min(1)).optional(),
    allSeverities: z
      .array(z.enum(['low', 'medium', 'high', 'critical']))
      .optional(),
    titleContains: z.array(z.string().min(1)).optional(),
    summaryContains: z.array(z.string().min(1)).optional(),
    primaryLocation: z
      .object({
        line: z.number().int().positive(),
        column: z.number().int().positive(),
      })
      .strict()
      .optional(),
  })
  .strict();

const ruleSpecFixtureSchema = z
  .object({
    name: z.string().min(1),
    sourcePath: z.string().min(1).optional(),
    observationPath: z.string().min(1).optional(),
    workspacePath: z.string().min(1).optional(),
    expect: ruleSpecFixtureExpectationSchema,
  })
  .strict()
  .superRefine((value, context) => {
    const declaredSources = [
      value.sourcePath,
      value.observationPath,
      value.workspacePath,
    ].filter(
      (entry): entry is string => typeof entry === 'string' && entry.length > 0,
    );

    if (declaredSources.length !== 1) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          'Each fixture must declare exactly one of sourcePath, observationPath, or workspacePath.',
        path: ['sourcePath'],
      });
    }
  });

export const ruleSpecSchema = z
  .object({
    apiVersion: z.literal('critiq.dev/v1alpha1'),
    kind: z.literal('RuleSpec'),
    rulePath: z.string().min(1),
    fixtures: z.array(ruleSpecFixtureSchema).min(1),
  })
  .strict();

export type RuleSpecFixtureExpectation = z.infer<
  typeof ruleSpecFixtureExpectationSchema
>;
export type RuleSpecFixture = z.infer<typeof ruleSpecFixtureSchema>;
export type RuleSpec = z.infer<typeof ruleSpecSchema>;

export interface RuleSpecValidationIssue {
  path: string;
  code: string;
  message: string;
}

export type RuleSpecValidationResult =
  | {
      success: true;
      data: RuleSpec;
    }
  | {
      success: false;
      issues: RuleSpecValidationIssue[];
    };

export interface LoadedRuleSpec {
  path: string;
  uri: string;
  spec: RuleSpec;
}

export type LoadRuleSpecResult =
  | {
      success: true;
      data: LoadedRuleSpec;
    }
  | {
      success: false;
      diagnostics: Diagnostic[];
    };

export interface RuleAssertionFailure {
  assertion:
    | 'findingCount'
    | 'allRuleIds'
    | 'allSeverities'
    | 'titleContains'
    | 'summaryContains'
    | 'primaryLocation';
  message: string;
  expected?: unknown;
  received?: unknown;
}

export interface EmittedFindingRecord {
  title: string;
  summary: string;
  severity: string;
  ruleId: string;
  primaryLocation: {
    line: number;
    column: number;
  };
}

export interface RuleSpecFixtureResult {
  name: string;
  fixturePath: string;
  sourceKind: 'source' | 'observation' | 'workspace';
  success: boolean;
  matches: EvaluationMatch[];
  emittedFindings: EmittedFindingRecord[];
  assertionFailures: RuleAssertionFailure[];
  diagnostics: Diagnostic[];
  buildIssues: BuildFindingIssue[];
}

export interface RuleSpecRunResult {
  specPath: string;
  rulePath: string;
  success: boolean;
  fixtureResults: RuleSpecFixtureResult[];
  diagnostics: Diagnostic[];
}

function readTextFile(path: string): string {
  return readFileSync(path, 'utf8');
}

function toPointer(path: Array<string | number>): string {
  return path.length === 0 ? '/' : `/${path.join('/')}`;
}

function createPathDiagnostic(
  code: string,
  message: string,
  path?: string,
): Diagnostic {
  return createDiagnostic({
    code,
    message,
    details: path ? { path } : undefined,
  });
}

function normalizeSpecIssue(issue: z.ZodIssue): RuleSpecValidationIssue {
  return {
    path: toPointer(issue.path),
    code: issue.code,
    message: issue.message,
  };
}

function validateObservationFixture(
  fixturePath: string,
  text: string,
): Diagnostic[] | AnalyzedFile {
  let parsed: unknown;

  try {
    parsed = JSON.parse(text);
  } catch (error) {
    return [
      createPathDiagnostic(
        'harness.fixture.invalid-observation-json',
        error instanceof Error ? error.message : 'Invalid observation JSON.',
        fixturePath,
      ),
    ];
  }

  const validated = analyzedFileSchema.safeParse(parsed);

  if (!validated.success) {
    return validated.error.issues.map((issue) =>
      createPathDiagnostic(
        'harness.fixture.invalid-observation',
        `${toPointer(issue.path)} ${issue.message}`,
        fixturePath,
      ),
    );
  }

  return validated.data as AnalyzedFile;
}

function analyzeSourceFixture(
  fixturePath: string,
  text: string,
  adapterRegistry: SourceAdapterRegistry,
): Diagnostic[] | AnalyzedFile {
  const extension = extname(fixturePath).toLowerCase();
  const adapter = adapterRegistry.findAdapterForPath(fixturePath);

  if (!adapter) {
    return [
      createPathDiagnostic(
        'harness.fixture.unsupported-source',
        `Unsupported source fixture extension: ${extension || '<none>'}.`,
        fixturePath,
      ),
    ];
  }

  const result = adapter.analyze(fixturePath, text);

  return result.success
    ? result.data
    : (result as Extract<typeof result, { success: false }>).diagnostics;
}

function analyzeWorkspaceFixture(
  workspaceRoot: string,
  adapterRegistry: SourceAdapterRegistry,
): Diagnostic[] | AnalyzedFile[] {
  const supportedFiles = walkFiles(workspaceRoot)
    .map((absolutePath) => {
      const displayPath = toDisplayPath(workspaceRoot, absolutePath);

      return {
        absolutePath,
        displayPath,
        adapter: adapterRegistry.findAdapterForPath(displayPath),
      };
    })
    .filter(
      (entry): entry is {
        absolutePath: string;
        displayPath: string;
        adapter: NonNullable<ReturnType<SourceAdapterRegistry['findAdapterForPath']>>;
      } => Boolean(entry.adapter),
    );

  if (supportedFiles.length === 0) {
    return [
      createPathDiagnostic(
        'harness.fixture.unsupported-workspace',
        'No supported source files were found in the workspace fixture.',
        workspaceRoot,
      ),
    ];
  }

  const diagnostics: Diagnostic[] = [];
  const analyzedFiles: AnalyzedFile[] = [];

  for (const entry of supportedFiles) {
    const textOrFailure = readFixtureText(entry.absolutePath);

    if (Array.isArray(textOrFailure)) {
      diagnostics.push(...textOrFailure);
      continue;
    }

    const result = entry.adapter.analyze(entry.displayPath, textOrFailure);

    if (!result.success) {
      const failure = result as Extract<typeof result, { success: false }>;

      diagnostics.push(...failure.diagnostics);
      continue;
    }

    analyzedFiles.push(result.data);
  }

  if (diagnostics.length > 0) {
    return diagnostics;
  }

  return augmentProjectFacts(analyzedFiles, {
    scopeMode: 'repo',
    availableTestPaths: new Set(
      analyzedFiles.map((file) => file.path).filter((path) => isTestPath(path)),
    ),
  });
}

function readFixtureText(fixturePath: string): string | Diagnostic[] {
  try {
    return readTextFile(fixturePath);
  } catch (error) {
    return [
      createPathDiagnostic(
        'runtime.internal.error',
        error instanceof Error
          ? error.message
          : 'Unexpected fixture file read failure.',
        fixturePath,
      ),
    ];
  }
}

function toEmittedFindingRecords(
  buildResults: BuildFindingResult[],
): EmittedFindingRecord[] {
  return buildResults.flatMap((result) =>
    result.success
      ? [
          {
            title: result.finding.title,
            summary: result.finding.summary,
            severity: result.finding.severity,
            ruleId: result.finding.rule.id,
            primaryLocation: {
              line: result.finding.locations.primary.startLine,
              column: result.finding.locations.primary.startColumn,
            },
          },
        ]
      : [],
  );
}

function compareStringArrays(
  assertion: RuleAssertionFailure['assertion'],
  label: string,
  expected: string[] | undefined,
  received: string[],
): RuleAssertionFailure[] {
  if (!expected) {
    return [];
  }

  const normalizedExpected = [...expected].sort();
  const normalizedReceived = [...received].sort();

  return JSON.stringify(normalizedExpected) === JSON.stringify(normalizedReceived)
    ? []
    : [
        {
          assertion,
          message: `Expected ${label} to match exactly.`,
          expected: normalizedExpected,
          received: normalizedReceived,
        },
      ];
}

function compareContainment(
  assertion: RuleAssertionFailure['assertion'],
  label: string,
  expectedSubstrings: string[] | undefined,
  receivedValues: string[],
): RuleAssertionFailure[] {
  if (!expectedSubstrings) {
    return [];
  }

  return expectedSubstrings.flatMap((substring) =>
    receivedValues.some((value) => value.includes(substring))
      ? []
      : [
          {
            assertion,
            message: `Expected at least one ${label} to contain \`${substring}\`.`,
            expected: substring,
            received: receivedValues,
          },
        ],
  );
}

function assertFixtureExpectations(
  fixture: RuleSpecFixture,
  emittedFindings: EmittedFindingRecord[],
): RuleAssertionFailure[] {
  const failures: RuleAssertionFailure[] = [];
  const { expect } = fixture;

  if (emittedFindings.length !== expect.findingCount) {
    failures.push({
      assertion: 'findingCount',
      message: 'Expected findingCount to match exactly.',
      expected: expect.findingCount,
      received: emittedFindings.length,
    });
  }

  failures.push(
    ...compareStringArrays(
      'allRuleIds',
      'rule ids',
      expect.allRuleIds,
      emittedFindings.map((finding) => finding.ruleId),
    ),
    ...compareStringArrays(
      'allSeverities',
      'severities',
      expect.allSeverities,
      emittedFindings.map((finding) => finding.severity),
    ),
    ...compareContainment(
      'titleContains',
      'finding title',
      expect.titleContains,
      emittedFindings.map((finding) => finding.title),
    ),
    ...compareContainment(
      'summaryContains',
      'finding summary',
      expect.summaryContains,
      emittedFindings.map((finding) => finding.summary),
    ),
  );

  if (expect.primaryLocation) {
    const received = emittedFindings[0]?.primaryLocation;

    if (
      !received ||
      received.line !== expect.primaryLocation.line ||
      received.column !== expect.primaryLocation.column
    ) {
      failures.push({
        assertion: 'primaryLocation',
        message: 'Expected the primary finding location to match exactly.',
        expected: expect.primaryLocation,
        received: received ?? null,
      });
    }
  }

  return failures;
}

function formatAssertionFailure(failure: RuleAssertionFailure): string {
  const lines = [`- ${failure.assertion}: ${failure.message}`];

  if (failure.expected !== undefined) {
    lines.push(`  expected: ${JSON.stringify(failure.expected)}`);
  }

  if (failure.received !== undefined) {
    lines.push(`  received: ${JSON.stringify(failure.received)}`);
  }

  return lines.join('\n');
}

function analyzeFixture(
  specDirectory: string,
  fixture: RuleSpecFixture,
  adapterRegistry: SourceAdapterRegistry,
): {
  sourceKind: 'source' | 'observation' | 'workspace';
  fixturePath: string;
  diagnostics?: Diagnostic[];
  analyzedFiles?: AnalyzedFile[];
} {
  const sourceKind = fixture.sourcePath
    ? 'source'
    : fixture.observationPath
      ? 'observation'
      : 'workspace';
  const declaredPath =
    fixture.sourcePath ?? fixture.observationPath ?? fixture.workspacePath ?? '';
  const fixturePath = resolve(specDirectory, declaredPath);

  if (sourceKind === 'workspace') {
    const workspaceAnalysis = analyzeWorkspaceFixture(fixturePath, adapterRegistry);

    return {
      sourceKind,
      fixturePath,
      ...(Array.isArray(workspaceAnalysis) &&
      workspaceAnalysis.every((entry) => 'path' in entry && 'language' in entry)
        ? {
            analyzedFiles: workspaceAnalysis,
          }
        : {
            diagnostics: workspaceAnalysis as Diagnostic[],
          }),
    };
  }

  const textOrFailure = readFixtureText(fixturePath);

  if (Array.isArray(textOrFailure)) {
    return {
      sourceKind,
      fixturePath,
      diagnostics: textOrFailure,
    };
  }

  const analyzedFile =
    sourceKind === 'source'
      ? analyzeSourceFixture(fixturePath, textOrFailure, adapterRegistry)
      : validateObservationFixture(fixturePath, textOrFailure);

  return {
    sourceKind,
    fixturePath,
    ...(Array.isArray(analyzedFile)
      ? {
          diagnostics: analyzedFile,
        }
      : {
          analyzedFiles: [analyzedFile],
        }),
  };
}

export interface RunRuleSpecOptions {
  adapterRegistry?: SourceAdapterRegistry;
}

export function validateRuleSpec(input: unknown): RuleSpecValidationResult {
  const result = ruleSpecSchema.safeParse(input);

  if (result.success) {
    return {
      success: true,
      data: result.data,
    };
  }

  return {
    success: false,
    issues: result.error.issues.map(normalizeSpecIssue),
  };
}

export function loadRuleSpec(path: string): LoadRuleSpecResult {
  try {
    const text = readTextFile(path);
    const uri = pathToFileURL(path).href;
    const loaded = loadYamlText(text, uri);

    if (!loaded.success) {
      const failure = loaded as Extract<typeof loaded, { success: false }>;
      return {
        success: false,
        diagnostics: failure.issues.map((issue) =>
          createDiagnostic({
            code: `harness.rulespec.${issue.kind}`,
            message: issue.message,
            sourceSpan: issue.sourceSpan,
            details: issue.details,
          }),
        ),
      };
    }

    const validation = validateRuleSpec(loaded.data);

    if (!validation.success) {
      const failure = validation as Extract<
        RuleSpecValidationResult,
        { success: false }
      >;
      return {
        success: false,
        diagnostics: failure.issues.map((issue) =>
          createDiagnostic({
            code: `harness.rulespec.${issue.code}`,
            message: issue.message,
            jsonPointer: issue.path,
          }),
        ),
      };
    }

    return {
      success: true,
      data: {
        path,
        uri,
        spec: validation.data,
      },
    };
  } catch (error) {
    return {
      success: false,
      diagnostics: [
        createPathDiagnostic(
          'runtime.internal.error',
          error instanceof Error ? error.message : 'Unexpected RuleSpec load failure.',
          path,
        ),
      ],
    };
  }
}

export function runRuleSpec(
  path: string,
  options: RunRuleSpecOptions = {},
): RuleSpecRunResult {
  const adapterRegistry =
    options.adapterRegistry ?? createDefaultSourceAdapterRegistry();
  const loadedSpec = loadRuleSpec(path);

  if (!loadedSpec.success) {
    const failure = loadedSpec as Extract<LoadRuleSpecResult, { success: false }>;
    return {
      specPath: path,
      rulePath: '',
      success: false,
      fixtureResults: [],
      diagnostics: failure.diagnostics,
    };
  }

  const specDirectory = dirname(loadedSpec.data.path);
  const absoluteRulePath = resolve(specDirectory, loadedSpec.data.spec.rulePath);
  const loadedRule = loadRuleFile(absoluteRulePath);

  if (!loadedRule.success) {
    const failure = loadedRule as Extract<typeof loadedRule, { success: false }>;
    return {
      specPath: loadedSpec.data.path,
      rulePath: absoluteRulePath,
      success: false,
      fixtureResults: [],
      diagnostics: failure.diagnostics,
    };
  }

  const validatedRule = validateLoadedRuleDocument(loadedRule.data);

  if (!validatedRule.success) {
    return {
      specPath: loadedSpec.data.path,
      rulePath: absoluteRulePath,
      success: false,
      fixtureResults: [],
      diagnostics: validatedRule.diagnostics,
    };
  }

  const normalizedRule = normalizeRuleDocument(validatedRule.data).rule;
  const fixtureResults = loadedSpec.data.spec.fixtures.map((fixture) => {
    const analysis = analyzeFixture(specDirectory, fixture, adapterRegistry);

    if (analysis.diagnostics) {
      return {
        name: fixture.name,
        fixturePath: analysis.fixturePath,
        sourceKind: analysis.sourceKind,
        success: false,
        matches: [],
        emittedFindings: [],
        assertionFailures: [],
        diagnostics: analysis.diagnostics,
        buildIssues: [],
      } satisfies RuleSpecFixtureResult;
    }

    const analyzedFiles = analysis.analyzedFiles ?? [];
    const evaluationResults = analyzedFiles.map((analyzedFile) => ({
      analyzedFile,
      matches: evaluateRule(normalizedRule, analyzedFile),
    }));
    const matches = evaluationResults.flatMap((result) => result.matches);
    const buildResults = evaluationResults.flatMap((result) =>
      result.matches.map((match) =>
        buildFinding(normalizedRule, result.analyzedFile, match),
      ),
    );
    const buildIssues = buildResults.flatMap((result) =>
      result.success
        ? []
        : (result as Extract<typeof result, { success: false }>).issues,
    );
    const emittedFindings = toEmittedFindingRecords(buildResults);
    const assertionFailures = assertFixtureExpectations(fixture, emittedFindings);
    const success = buildIssues.length === 0 && assertionFailures.length === 0;

    return {
      name: fixture.name,
      fixturePath: analysis.fixturePath,
      sourceKind: analysis.sourceKind,
      success,
      matches,
      emittedFindings,
      assertionFailures,
      diagnostics: [],
      buildIssues,
    } satisfies RuleSpecFixtureResult;
  });

  return {
    specPath: loadedSpec.data.path,
    rulePath: absoluteRulePath,
    success: fixtureResults.every((result) => result.success),
    fixtureResults,
    diagnostics: [],
  };
}

export function formatRuleSpecRunForTerminal(result: RuleSpecRunResult): string {
  const lines = [
    `RuleSpec: ${result.specPath}`,
    result.rulePath ? `Rule: ${result.rulePath}` : 'Rule: unavailable',
  ];

  if (result.diagnostics.length > 0) {
    lines.push('', formatDiagnosticsForTerminal(result.diagnostics));
    return lines.join('\n');
  }

  for (const fixtureResult of result.fixtureResults) {
    lines.push(
      '',
      `${fixtureResult.success ? 'PASS' : 'FAIL'} ${fixtureResult.name} (${fixtureResult.sourceKind})`,
      `Fixture: ${fixtureResult.fixturePath}`,
    );

    if (fixtureResult.diagnostics.length > 0) {
      lines.push(formatDiagnosticsForTerminal(fixtureResult.diagnostics));
    }

    if (fixtureResult.buildIssues.length > 0) {
      lines.push('Build issues:');
      lines.push(
        ...fixtureResult.buildIssues.map(
          (issue) => `- ${issue.code}: ${issue.message}${issue.details ? ` ${JSON.stringify(issue.details)}` : ''}`,
        ),
      );
    }

    if (fixtureResult.assertionFailures.length > 0) {
      lines.push('Assertion failures:');
      lines.push(...fixtureResult.assertionFailures.map(formatAssertionFailure));
    }

    if (fixtureResult.success) {
      lines.push(
        `Findings: ${fixtureResult.emittedFindings.length}`,
        `Matches: ${fixtureResult.matches.length}`,
      );
    }
  }

  lines.push('', `Success: ${result.success}`);

  return lines.join('\n');
}

export function formatRuleSpecRunAsJson(result: RuleSpecRunResult): Record<string, unknown> {
  return {
    specPath: result.specPath,
    rulePath: result.rulePath,
    success: result.success,
    diagnostics: result.diagnostics,
    fixtureResults: result.fixtureResults.map((fixtureResult) => ({
      name: fixtureResult.name,
      fixturePath: fixtureResult.fixturePath,
      sourceKind: fixtureResult.sourceKind,
      success: fixtureResult.success,
      matchCount: fixtureResult.matches.length,
      emittedFindings: fixtureResult.emittedFindings,
      diagnostics: fixtureResult.diagnostics,
      buildIssues: fixtureResult.buildIssues,
      assertionFailures: fixtureResult.assertionFailures,
    })),
  };
}

export function workspaceHarnessPackageName(): string {
  return '@critiq/testing-harness';
}

export function relativeRuleSpecPath(rootDirectory: string, absolutePath: string): string {
  return relative(rootDirectory, absolutePath) || absolutePath;
}
