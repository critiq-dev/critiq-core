#!/usr/bin/env node

import {
  aggregateDiagnostics,
  formatDiagnosticsForTerminal,
  type Diagnostic,
} from '@critiq/core-diagnostics';
import { normalizeRuleDocument } from '@critiq/core-ir';
import type { FindingV0 } from '@critiq/core-finding-schema';
import {
  runCheckCommand,
  type CheckCommandEnvelope,
  type CheckOverallRuleResult,
} from '@critiq/check-runner';
import {
  formatRuleSpecRunAsJson,
  formatRuleSpecRunForTerminal,
  runRuleSpec,
} from '@critiq/testing-harness';
import {
  loadRuleFile,
  summarizeValidatedRuleDocument,
  validateLoadedRuleDocumentContract,
  validateRuleDocumentSemantics,
  type LoadRuleResult,
  type RuleTemplateVariableMap,
  validateLoadedRuleDocument,
} from '@critiq/core-rules-dsl';
import { minimatch } from 'minimatch';
import { readdirSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

type OutputFormat = 'pretty' | 'json';
type PhaseStatus = 'success' | 'failure' | 'skipped';

interface CliRuntime {
  cwd?: string;
  writeStdout?: (message: string) => void;
  writeStderr?: (message: string) => void;
}

interface ParsedArguments {
  positionals: string[];
  format: OutputFormat;
  help: boolean;
  baseRef?: string;
  headRef?: string;
}

interface CliResultEnvelope {
  command: string;
  format: OutputFormat;
  exitCode: number;
}

interface ValidateFileResult {
  path: string;
  uri: string;
  success: boolean;
  diagnostics: Diagnostic[];
}

interface ValidateCommandEnvelope extends CliResultEnvelope {
  target: string;
  matchedFileCount: number;
  results: ValidateFileResult[];
  diagnostics: Diagnostic[];
}

interface TestSpecResult {
  specPath: string;
  success: boolean;
  diagnostics: Diagnostic[];
  run: ReturnType<typeof runRuleSpec>;
  result: ReturnType<typeof formatRuleSpecRunAsJson>;
}

interface TestCommandEnvelope extends CliResultEnvelope {
  target: string;
  matchedFileCount: number;
  results: TestSpecResult[];
  diagnostics: Diagnostic[];
}

interface ExplainParsedSummary {
  path: string;
  uri: string;
  ruleId: string | null;
  title: string | null;
  summary: string | null;
  phases: {
    load: PhaseStatus;
    contractValidation: PhaseStatus;
    semanticValidation: PhaseStatus;
    normalization: PhaseStatus;
  };
}

interface ExplainSemanticStatus {
  success: boolean;
  diagnostics: Diagnostic[];
}

interface NormalizeCommandEnvelope extends CliResultEnvelope {
  file: {
    path: string;
    uri: string;
  };
  parsedSummary: ExplainParsedSummary;
  semanticStatus: ExplainSemanticStatus;
  normalizedRule: ReturnType<typeof normalizeRuleDocument>['rule'] | null;
  ruleHash: string | null;
  diagnostics: Diagnostic[];
}

interface ExplainCommandEnvelope extends CliResultEnvelope {
  file: {
    path: string;
    uri: string;
  };
  parsedSummary: ExplainParsedSummary;
  semanticStatus: ExplainSemanticStatus;
  normalizedRule: ReturnType<typeof normalizeRuleDocument>['rule'] | null;
  ruleHash: string | null;
  templateVariables: RuleTemplateVariableMap;
  diagnostics: Diagnostic[];
}

interface SingleFileCommandState {
  displayPath: string;
  uri: string;
  parsedSummary: ExplainParsedSummary;
  semanticStatus: ExplainSemanticStatus;
  normalizedRule: ReturnType<typeof normalizeRuleDocument>['rule'] | null;
  ruleHash: string | null;
  templateVariables: RuleTemplateVariableMap;
  diagnostics: Diagnostic[];
}

const DEFAULT_TEMPLATE_VARIABLES: RuleTemplateVariableMap = {
  'emit.message.title': [],
  'emit.message.summary': [],
  'emit.message.detail': [],
  'emit.remediation.summary': [],
};

const defaultRuntime: Required<CliRuntime> = {
  cwd: process.cwd(),
  writeStdout: (message: string) => {
    process.stdout.write(`${message}\n`);
  },
  writeStderr: (message: string) => {
    process.stderr.write(`${message}\n`);
  },
};

function hasGlobMagic(value: string): boolean {
  return /[*?[\]{}]/.test(value);
}

function toPosixPath(value: string): string {
  return value.split(sep).join('/');
}

function toDisplayPath(cwd: string, absolutePath: string): string {
  const relativePath = toPosixPath(relative(cwd, absolutePath));

  if (
    relativePath.length > 0 &&
    !relativePath.startsWith('..') &&
    !isAbsolute(relativePath)
  ) {
    return relativePath;
  }

  return toPosixPath(absolutePath);
}

function createParsedSummary(path: string, uri: string): ExplainParsedSummary {
  return {
    path,
    uri,
    ruleId: null,
    title: null,
    summary: null,
    phases: {
      load: 'skipped',
      contractValidation: 'skipped',
      semanticValidation: 'skipped',
      normalization: 'skipped',
    },
  };
}

function parseArguments(args: readonly string[]): ParsedArguments | Diagnostic {
  const positionals: string[] = [];
  let format: OutputFormat = 'pretty';
  let help = false;
  let baseRef: string | undefined;
  let headRef: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];

    if (value === '--help' || value === 'help') {
      help = true;
      continue;
    }

    if (value.startsWith('--format=')) {
      const nextFormat = value.slice('--format='.length);

      if (nextFormat !== 'pretty' && nextFormat !== 'json') {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message: `Unsupported format: ${nextFormat}`,
          details: {
            expected: ['pretty', 'json'],
            received: nextFormat,
          },
        };
      }

      format = nextFormat;
      continue;
    }

    if (value === '--format') {
      const nextFormat = args[index + 1];

      if (nextFormat !== 'pretty' && nextFormat !== 'json') {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message: 'Expected `--format` to be followed by `pretty` or `json`.',
          details: {
            expected: ['pretty', 'json'],
            received: nextFormat ?? null,
          },
        };
      }

      format = nextFormat;
      index += 1;
      continue;
    }

    if (value.startsWith('--base=')) {
      const nextBaseRef = value.slice('--base='.length);

      if (nextBaseRef.trim().length === 0) {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message: 'Expected `--base` to be followed by a git ref.',
          details: {
            received: nextBaseRef,
          },
        };
      }

      baseRef = nextBaseRef;
      continue;
    }

    if (value === '--base') {
      const nextBaseRef = args[index + 1];

      if (!nextBaseRef || nextBaseRef.startsWith('--')) {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message: 'Expected `--base` to be followed by a git ref.',
          details: {
            received: nextBaseRef ?? null,
          },
        };
      }

      baseRef = nextBaseRef;
      index += 1;
      continue;
    }

    if (value.startsWith('--head=')) {
      const nextHeadRef = value.slice('--head='.length);

      if (nextHeadRef.trim().length === 0) {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message: 'Expected `--head` to be followed by a git ref.',
          details: {
            received: nextHeadRef,
          },
        };
      }

      headRef = nextHeadRef;
      continue;
    }

    if (value === '--head') {
      const nextHeadRef = args[index + 1];

      if (!nextHeadRef || nextHeadRef.startsWith('--')) {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message: 'Expected `--head` to be followed by a git ref.',
          details: {
            received: nextHeadRef ?? null,
          },
        };
      }

      headRef = nextHeadRef;
      index += 1;
      continue;
    }

    if (value.startsWith('--')) {
      return {
        code: 'cli.argument.invalid',
        severity: 'error',
        message: `Unknown option: ${value}`,
      };
    }

    positionals.push(value);
  }

  return {
    positionals,
    format,
    help,
    baseRef,
    headRef,
  };
}

function formatTemplateVariablesForTerminal(
  templateVariables: RuleTemplateVariableMap,
): string {
  return Object.entries(templateVariables)
    .map(([field, references]) => {
      if (references.length === 0) {
        return `${field}\n  - none`;
      }

      return [
        field,
        ...references.map(
          (reference) => `  - ${reference.raw} (${reference.expression})`,
        ),
      ].join('\n');
    })
    .join('\n');
}

function renderHelpMessage(): string {
  return [
    'critiq CLI',
    '',
    'Usage:',
    '  critiq check [target] [--base <git-ref>] [--head <git-ref>] [--format pretty|json]',
    '  critiq rules validate <glob> [--format pretty|json]',
    '  critiq rules test [glob] [--format pretty|json]',
    '  critiq rules normalize <file> [--format pretty|json]',
    '  critiq rules explain <file> [--format pretty|json]',
    '  critiq help',
    '',
    'Exit codes:',
    '  0 success',
    '  1 user/input errors or validation diagnostics',
    '  2 internal/runtime errors',
  ].join('\n');
}

function renderJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function renderValidatePretty(envelope: ValidateCommandEnvelope): string {
  const lines = [
    `Validated ${envelope.matchedFileCount} file(s) for \`${envelope.target}\``,
  ];

  for (const result of envelope.results) {
    lines.push('', result.path);

    if (result.success) {
      lines.push('OK');
      continue;
    }

    lines.push(formatDiagnosticsForTerminal(result.diagnostics));
  }

  lines.push('', `Exit code: ${envelope.exitCode}`);

  return lines.join('\n');
}

function renderTestPretty(envelope: TestCommandEnvelope): string {
  const lines = [
    `Tested ${envelope.matchedFileCount} spec file(s) for \`${envelope.target}\``,
  ];

  for (const result of envelope.results) {
    lines.push('', formatRuleSpecRunForTerminal(result.run));
  }

  lines.push('', `Exit code: ${envelope.exitCode}`);

  return lines.join('\n');
}

function humanizeRuleId(ruleId: string): string {
  const rawName = ruleId.split('.').at(-1) ?? ruleId;

  return rawName
    .split(/[-_]+/)
    .filter((part) => part.length > 0)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

const ansi = {
  reset: '\u001b[0m',
  red: '\u001b[31m',
  green: '\u001b[32m',
  dim: '\u001b[2m',
  bold: '\u001b[1m',
};

function colorize(
  color: keyof typeof ansi,
  value: string,
  options: { bold?: boolean } = {},
): string {
  const prefixes = [options.bold ? ansi.bold : '', ansi[color]].join('');

  return `${prefixes}${value}${ansi.reset}`;
}

function renderFindingCodeFrame(
  sourceText: string,
  location: FindingV0['locations']['primary'],
): string[] {
  const lines = sourceText.split(/\r?\n/);
  const lineNumberWidth = String(location.endLine + 1).length;
  const startLine = Math.max(location.startLine - 1, 1);
  const endLine = Math.min(location.endLine + 1, lines.length);
  const frameLines: string[] = [];

  for (let lineNumber = startLine; lineNumber <= endLine; lineNumber += 1) {
    const lineText = lines[lineNumber - 1] ?? '';
    const marker = lineNumber === location.startLine ? '>' : ' ';

    frameLines.push(
      `    ${marker} ${String(lineNumber).padStart(lineNumberWidth, ' ')} | ${lineText}`,
    );

    if (lineNumber === location.startLine) {
      const caretStart = Math.max(location.startColumn, 1);
      const caretWidth = Math.max(
        1,
        lineNumber === location.endLine
          ? location.endColumn - location.startColumn
          : Math.max(lineText.length - location.startColumn + 2, 1),
      );

      frameLines.push(
        `      ${' '.repeat(lineNumberWidth)} | ${' '.repeat(caretStart - 1)}${'^'.repeat(caretWidth)}`,
      );
    }
  }

  return frameLines;
}

function renderCheckPretty(
  envelope: CheckCommandEnvelope,
  overallRuleResults: readonly CheckOverallRuleResult[],
  sourceTextsByPath: ReadonlyMap<string, string>,
): string {
  const overallStatus = overallRuleResults.every(
    (result) => result.status === 'passed',
  )
    ? 'PASS'
    : 'FAIL';

  const lines: string[] = [
    '',
    `${colorize(overallStatus === 'PASS' ? 'green' : 'red', overallStatus, { bold: true })} Rule Results`,
  ];

  for (const ruleResult of overallRuleResults) {
    lines.push(
      ruleResult.status === 'failed'
        ? ` ${colorize('red', '✕')} ${humanizeRuleId(ruleResult.ruleId)}`
        : ` ${colorize('green', '✓')} ${humanizeRuleId(ruleResult.ruleId)}`,
    );
  }

  if (envelope.findings.length > 0) {
    const findingsByPath = new Map<string, FindingV0[]>();

    for (const finding of envelope.findings) {
      const findingsForPath =
        findingsByPath.get(finding.locations.primary.path) ?? [];
      findingsForPath.push(finding);
      findingsByPath.set(finding.locations.primary.path, findingsForPath);
    }

    for (const [path, findings] of Array.from(findingsByPath.entries()).sort(
      ([left], [right]) => left.localeCompare(right),
    )) {
      lines.push('', `${colorize('red', `● ${path}`, { bold: true })}`);

      for (const finding of findings) {
        const sourceText = sourceTextsByPath.get(finding.locations.primary.path);

        lines.push(
          `  ${colorize('red', '✕')} ${humanizeRuleId(finding.rule.id)}`,
          `    ${finding.summary}`,
        );

        if (sourceText) {
          lines.push(
            ...renderFindingCodeFrame(sourceText, finding.locations.primary),
          );
        }

        lines.push(
          `    at ${finding.locations.primary.path}:${finding.locations.primary.startLine}:${finding.locations.primary.startColumn}`,
        );
      }
    }
  }

  if (envelope.diagnostics.length > 0) {
    lines.push(
      '',
      'Diagnostics',
      formatDiagnosticsForTerminal(envelope.diagnostics),
    );
  }

  const failedFileCount = new Set(
    envelope.findings.map((finding) => finding.locations.primary.path),
  ).size;
  const failedRuleCount = overallRuleResults.filter(
    (ruleResult) => ruleResult.status === 'failed',
  ).length;
  const passedRuleCount = Math.max(
    overallRuleResults.length - failedRuleCount,
    0,
  );
  const passedFileCount = Math.max(
    envelope.scannedFileCount - failedFileCount,
    0,
  );

  lines.push(
    '',
    `Checked ${envelope.scannedFileCount} file(s) against ${envelope.matchedRuleCount} rule(s)`,
    `Rules:       ${colorize('red', `${failedRuleCount} failed`, { bold: true })}, ${colorize('green', `${passedRuleCount} passed`, { bold: true })}, ${overallRuleResults.length} total`,
    `Files:       ${colorize('red', `${failedFileCount} failed`, { bold: true })}, ${colorize('green', `${passedFileCount} passed`, { bold: true })}, ${envelope.scannedFileCount} total`,
    `Findings:    ${envelope.findingCount} total`,
    envelope.scope.mode === 'diff'
      ? `Scope:       diff (${envelope.scope.base}..${envelope.scope.head}, ${envelope.scope.changedFileCount} changed file(s))`
      : `Scope:       repo`,
  );

  return lines.join('\n');
}

function renderSingleFilePretty(
  heading: 'normalize' | 'explain',
  state: SingleFileCommandState,
): string {
  const lines = [
    'Parsed Summary',
    `Path: ${state.parsedSummary.path}`,
    `URI: ${state.parsedSummary.uri}`,
    `Rule ID: ${state.parsedSummary.ruleId ?? 'Unavailable'}`,
    `Title: ${state.parsedSummary.title ?? 'Unavailable'}`,
    `Summary: ${state.parsedSummary.summary ?? 'Unavailable'}`,
    `Load: ${state.parsedSummary.phases.load}`,
    `Contract validation: ${state.parsedSummary.phases.contractValidation}`,
    `Semantic validation: ${state.parsedSummary.phases.semanticValidation}`,
    `Normalization: ${state.parsedSummary.phases.normalization}`,
    '',
    'Semantic Status',
  ];

  if (state.semanticStatus.diagnostics.length === 0) {
    lines.push('No diagnostics.');
  } else {
    lines.push(formatDiagnosticsForTerminal(state.semanticStatus.diagnostics));
  }

  lines.push('', 'Normalized Rule');

  if (state.normalizedRule) {
    lines.push(renderJson(state.normalizedRule));
  } else {
    lines.push('Unavailable');
  }

  if (heading === 'explain') {
    lines.push('', 'Inferred Template Variables');
    lines.push(formatTemplateVariablesForTerminal(state.templateVariables));
  }

  return lines.join('\n');
}

function determineExitCode(diagnostics: readonly Diagnostic[]): number {
  if (
    diagnostics.some(
      (diagnostic) => diagnostic.code === 'runtime.internal.error',
    )
  ) {
    return 2;
  }

  if (
    diagnostics.some(
      (diagnostic) => diagnostic.severity === 'error',
    )
  ) {
    return 1;
  }

  return 0;
}

function isSkippableDirectory(name: string): boolean {
  return ['.git', '.nx', 'coverage', 'dist', 'node_modules'].includes(name);
}

function walkFiles(rootDirectory: string): string[] {
  const files: string[] = [];
  const queue = [rootDirectory];

  while (queue.length > 0) {
    const currentDirectory = queue.shift();

    if (!currentDirectory) {
      continue;
    }

    const entries = readdirSync(currentDirectory, { withFileTypes: true }).sort(
      (left, right) => left.name.localeCompare(right.name),
    );

    for (const entry of entries) {
      const absolutePath = resolve(currentDirectory, entry.name);

      if (entry.isDirectory()) {
        if (!isSkippableDirectory(entry.name)) {
          queue.push(absolutePath);
        }

        continue;
      }

      if (entry.isFile()) {
        files.push(absolutePath);
      }
    }
  }

  return files.sort((left, right) => left.localeCompare(right));
}

function resolveValidateTargets(
  cwd: string,
  target: string,
):
  | { success: true; files: string[] }
  | { success: false; diagnostics: Diagnostic[] } {
  const absoluteCandidate = resolve(cwd, target);

  if (!hasGlobMagic(target)) {
    try {
      if (!statSync(absoluteCandidate).isFile()) {
        return {
          success: false,
          diagnostics: [
            {
              code: 'cli.input.invalid',
              severity: 'error',
              message: `Expected a file path for \`${target}\`.`,
            },
          ],
        };
      }

      return {
        success: true,
        files: [absoluteCandidate],
      };
    } catch {
      return {
        success: false,
        diagnostics: [
          {
            code: 'cli.input.invalid',
            severity: 'error',
            message: `No files matched \`${target}\`.`,
            details: {
              target,
            },
          },
        ],
      };
    }
  }

  try {
    const matches = walkFiles(cwd).filter((absolutePath) =>
      minimatch(toDisplayPath(cwd, absolutePath), target, { dot: true }),
    );

    if (matches.length === 0) {
      return {
        success: false,
        diagnostics: [
          {
            code: 'cli.input.invalid',
            severity: 'error',
            message: `No files matched \`${target}\`.`,
            details: {
              target,
            },
          },
        ],
      };
    }

    return {
      success: true,
      files: matches,
    };
  } catch (error) {
    return {
      success: false,
      diagnostics: [
        {
          code: 'runtime.internal.error',
          severity: 'error',
          message:
            error instanceof Error
              ? error.message
              : 'Unexpected file discovery failure.',
          details: {
            target,
          },
        },
      ],
    };
  }
}

function resolveTestTargets(
  cwd: string,
  target: string | undefined,
):
  | { success: true; target: string; files: string[] }
  | { success: false; target: string; diagnostics: Diagnostic[] } {
  const resolvedTarget = target ?? '**/*.spec.yaml';
  const resolved = resolveValidateTargets(cwd, resolvedTarget);

  if (!resolved.success) {
    const failure = resolved as Extract<
      ReturnType<typeof resolveValidateTargets>,
      { success: false }
    >;
    return {
      success: false,
      target: resolvedTarget,
      diagnostics: failure.diagnostics,
    };
  }

  return {
    success: true,
    target: resolvedTarget,
    files: resolved.files,
  };
}

function isLegacyRulesArgument(value: string): boolean {
  return (
    hasGlobMagic(value) ||
    value.endsWith('.rule.yaml') ||
    value.endsWith('.rule.yml')
  );
}

function buildSingleFileState(
  absolutePath: string,
  cwd: string,
): SingleFileCommandState {
  const displayPath = toDisplayPath(cwd, absolutePath);
  const uri = pathToFileURL(absolutePath).href;
  const parsedSummary = createParsedSummary(displayPath, uri);
  const templateVariables = { ...DEFAULT_TEMPLATE_VARIABLES };

  const loadResult = loadRuleFile(absolutePath);

  parsedSummary.phases.load = loadResult.success ? 'success' : 'failure';

  if (!loadResult.success) {
    const failure = loadResult as Extract<LoadRuleResult, { success: false }>;

    return {
      displayPath,
      uri,
      parsedSummary,
      semanticStatus: {
        success: false,
        diagnostics: failure.diagnostics,
      },
      normalizedRule: null,
      ruleHash: null,
      templateVariables,
      diagnostics: failure.diagnostics,
    };
  }

  const contractValidation = validateLoadedRuleDocumentContract(
    loadResult.data,
  );

  parsedSummary.phases.contractValidation = contractValidation.success
    ? 'success'
    : 'failure';

  if (!contractValidation.success) {
    const failure = contractValidation as Extract<
      ReturnType<typeof validateLoadedRuleDocumentContract>,
      { success: false }
    >;

    return {
      displayPath,
      uri,
      parsedSummary,
      semanticStatus: {
        success: false,
        diagnostics: failure.diagnostics,
      },
      normalizedRule: null,
      ruleHash: null,
      templateVariables,
      diagnostics: failure.diagnostics,
    };
  }

  const explainSummary = summarizeValidatedRuleDocument(
    contractValidation.data,
  );

  parsedSummary.ruleId = explainSummary.ruleId;
  parsedSummary.title = explainSummary.title;
  parsedSummary.summary = explainSummary.summary;

  for (const [field, references] of Object.entries(
    explainSummary.templateVariables,
  )) {
    templateVariables[field as keyof RuleTemplateVariableMap] = references;
  }

  const semanticValidation = validateRuleDocumentSemantics(
    contractValidation.data,
  );

  parsedSummary.phases.semanticValidation = semanticValidation.success
    ? 'success'
    : 'failure';

  if (!semanticValidation.success) {
    return {
      displayPath,
      uri,
      parsedSummary,
      semanticStatus: {
        success: false,
        diagnostics: semanticValidation.diagnostics,
      },
      normalizedRule: null,
      ruleHash: null,
      templateVariables,
      diagnostics: semanticValidation.diagnostics,
    };
  }

  const normalized = normalizeRuleDocument(contractValidation.data);

  parsedSummary.phases.normalization = 'success';

  return {
    displayPath,
    uri,
    parsedSummary,
    semanticStatus: {
      success: true,
      diagnostics: [],
    },
    normalizedRule: normalized.rule,
    ruleHash: normalized.ruleHash,
    templateVariables,
    diagnostics: [],
  };
}

function resolveSingleFilePath(
  cwd: string,
  inputPath: string,
):
  | { success: true; absolutePath: string }
  | { success: false; diagnostics: Diagnostic[] } {
  if (hasGlobMagic(inputPath)) {
    return {
      success: false,
      diagnostics: [
        {
          code: 'cli.input.invalid',
          severity: 'error',
          message: `Expected a concrete file path for \`${inputPath}\`, not a glob.`,
        },
      ],
    };
  }

  return {
    success: true,
    absolutePath: resolve(cwd, inputPath),
  };
}

function validateResultForFileSafe(
  absolutePath: string,
  cwd: string,
): ValidateFileResult {
  const displayPath = toDisplayPath(cwd, absolutePath);
  const uri = pathToFileURL(absolutePath).href;
  const loaded = loadRuleFile(absolutePath);

  if (!loaded.success) {
    const failure = loaded as Extract<LoadRuleResult, { success: false }>;

    return {
      path: displayPath,
      uri,
      success: false,
      diagnostics: failure.diagnostics,
    };
  }

  const validated = validateLoadedRuleDocument(loaded.data);

  if (!validated.success) {
    return {
      path: displayPath,
      uri,
      success: false,
      diagnostics: validated.diagnostics,
    };
  }

  return {
    path: displayPath,
    uri,
    success: true,
    diagnostics: [],
  };
}

function handleValidate(
  target: string,
  format: OutputFormat,
  runtime: Required<CliRuntime>,
): number {
  const resolved = resolveValidateTargets(runtime.cwd, target);

  if (!resolved.success) {
    const failure = resolved as Extract<
      ReturnType<typeof resolveValidateTargets>,
      { success: false }
    >;
    const exitCode = determineExitCode(failure.diagnostics);
    const envelope: ValidateCommandEnvelope = {
      command: 'rules.validate',
      format,
      target,
      matchedFileCount: 0,
      results: [],
      diagnostics: aggregateDiagnostics(failure.diagnostics),
      exitCode: exitCode === 0 ? 1 : exitCode,
    };

    if (format === 'json') {
      runtime.writeStdout(renderJson(envelope));
    } else {
      runtime.writeStderr(formatDiagnosticsForTerminal(envelope.diagnostics));
    }

    return envelope.exitCode;
  }

  const results = resolved.files
    .sort((left, right) => left.localeCompare(right))
    .map((absolutePath) =>
      validateResultForFileSafe(absolutePath, runtime.cwd),
    );
  const diagnostics = aggregateDiagnostics(
    results.flatMap((result) => result.diagnostics),
  );
  const exitCode = determineExitCode(diagnostics);
  const envelope: ValidateCommandEnvelope = {
    command: 'rules.validate',
    format,
    target,
    matchedFileCount: results.length,
    results,
    diagnostics,
    exitCode,
  };

  if (format === 'json') {
    runtime.writeStdout(renderJson(envelope));
  } else {
    runtime.writeStdout(renderValidatePretty(envelope));
  }

  return exitCode;
}

function handleTest(
  target: string | undefined,
  format: OutputFormat,
  runtime: Required<CliRuntime>,
): number {
  const resolved = resolveTestTargets(runtime.cwd, target);

  if (!resolved.success) {
    const failure = resolved as Extract<
      ReturnType<typeof resolveTestTargets>,
      { success: false }
    >;
    const exitCode = determineExitCode(failure.diagnostics) || 1;
    const envelope: TestCommandEnvelope = {
      command: 'rules.test',
      format,
      target: failure.target,
      matchedFileCount: 0,
      results: [],
      diagnostics: aggregateDiagnostics(failure.diagnostics),
      exitCode,
    };

    if (format === 'json') {
      runtime.writeStdout(renderJson(envelope));
    } else {
      runtime.writeStderr(formatDiagnosticsForTerminal(envelope.diagnostics));
    }

    return exitCode;
  }

  const results = resolved.files
    .sort((left, right) => left.localeCompare(right))
    .map((absolutePath) => {
      const runResult = runRuleSpec(absolutePath);

      return {
        specPath: toDisplayPath(runtime.cwd, absolutePath),
        success: runResult.success,
        diagnostics: runResult.diagnostics,
        run: runResult,
        result: formatRuleSpecRunAsJson(runResult),
      } satisfies TestSpecResult;
    });
  const diagnostics = aggregateDiagnostics(
    results.flatMap((result) => [
      ...result.diagnostics,
      ...result.run.fixtureResults.flatMap(
        (fixtureResult) => fixtureResult.diagnostics,
      ),
    ]),
  );
  const hasFailures = results.some((result) => !result.success);
  const exitCode =
    diagnostics.length > 0
      ? determineExitCode(diagnostics)
      : hasFailures
        ? 1
        : 0;
  const envelope: TestCommandEnvelope = {
    command: 'rules.test',
    format,
    target: resolved.target,
    matchedFileCount: results.length,
    results,
    diagnostics,
    exitCode,
  };

  if (format === 'json') {
    runtime.writeStdout(renderJson(envelope));
  } else {
    runtime.writeStdout(renderTestPretty(envelope));
  }

  return exitCode;
}

function handleCheck(
  target: string | undefined,
  format: OutputFormat,
  runtime: Required<CliRuntime>,
  baseRef?: string,
  headRef?: string,
): number {
  const result = runCheckCommand({
    cwd: runtime.cwd,
    target,
    format,
    baseRef,
    headRef,
    catalogResolverBasePaths: [runtime.cwd],
  });

  if (format === 'json') {
    runtime.writeStdout(renderJson(result.envelope));
  } else if (result.envelope.exitCode > 0 && result.envelope.findingCount === 0) {
    runtime.writeStderr(formatDiagnosticsForTerminal(result.envelope.diagnostics));
  } else {
    runtime.writeStdout(
      renderCheckPretty(
        result.envelope,
        result.overallRuleResults,
        result.sourceTextsByPath,
      ),
    );
  }

  return result.envelope.exitCode;
}

function handleNormalizeOrExplain(
  command: 'normalize' | 'explain',
  inputPath: string,
  format: OutputFormat,
  runtime: Required<CliRuntime>,
): number {
  const resolved = resolveSingleFilePath(runtime.cwd, inputPath);

  if (!resolved.success) {
    const failure = resolved as Extract<
      ReturnType<typeof resolveSingleFilePath>,
      { success: false }
    >;
    const diagnostics = aggregateDiagnostics(failure.diagnostics);
    const exitCode = determineExitCode(diagnostics) || 1;
    const uri = pathToFileURL(resolve(runtime.cwd, inputPath)).href;
    const parsedSummary = createParsedSummary(inputPath, uri);
    const baseState: SingleFileCommandState = {
      displayPath: inputPath,
      uri,
      parsedSummary,
      semanticStatus: {
        success: false,
        diagnostics,
      },
      normalizedRule: null,
      ruleHash: null,
      templateVariables: { ...DEFAULT_TEMPLATE_VARIABLES },
      diagnostics,
    };

    const envelope =
      command === 'normalize'
        ? ({
            command: 'rules.normalize',
            format,
            file: {
              path: inputPath,
              uri,
            },
            parsedSummary,
            semanticStatus: baseState.semanticStatus,
            normalizedRule: null,
            ruleHash: null,
            diagnostics,
            exitCode,
          } satisfies NormalizeCommandEnvelope)
        : ({
            command: 'rules.explain',
            format,
            file: {
              path: inputPath,
              uri,
            },
            parsedSummary,
            semanticStatus: baseState.semanticStatus,
            normalizedRule: null,
            ruleHash: null,
            templateVariables: baseState.templateVariables,
            diagnostics,
            exitCode,
          } satisfies ExplainCommandEnvelope);

    if (format === 'json') {
      runtime.writeStdout(renderJson(envelope));
    } else {
      runtime.writeStderr(
        command === 'normalize'
          ? renderSingleFilePretty('normalize', baseState)
          : renderSingleFilePretty('explain', baseState),
      );
    }

    return exitCode;
  }

  const state = buildSingleFileState(resolved.absolutePath, runtime.cwd);
  const exitCode = determineExitCode(state.diagnostics);

  if (command === 'normalize') {
    const envelope: NormalizeCommandEnvelope = {
      command: 'rules.normalize',
      format,
      file: {
        path: state.displayPath,
        uri: state.uri,
      },
      parsedSummary: state.parsedSummary,
      semanticStatus: state.semanticStatus,
      normalizedRule: state.normalizedRule,
      ruleHash: state.ruleHash,
      diagnostics: state.diagnostics,
      exitCode,
    };

    if (format === 'json') {
      runtime.writeStdout(renderJson(envelope));
    } else {
      runtime.writeStdout(renderSingleFilePretty('normalize', state));
    }

    return exitCode;
  }

  const envelope: ExplainCommandEnvelope = {
    command: 'rules.explain',
    format,
    file: {
      path: state.displayPath,
      uri: state.uri,
    },
    parsedSummary: state.parsedSummary,
    semanticStatus: state.semanticStatus,
    normalizedRule: state.normalizedRule,
    ruleHash: state.ruleHash,
    templateVariables: state.templateVariables,
    diagnostics: state.diagnostics,
    exitCode,
  };

  if (format === 'json') {
    runtime.writeStdout(renderJson(envelope));
  } else {
    runtime.writeStdout(renderSingleFilePretty('explain', state));
  }

  return exitCode;
}

/**
 * Runs the Critiq CLI and returns a stable exit code.
 */
export function runCli(
  args: readonly string[] = process.argv.slice(2),
  runtime: CliRuntime = {},
): number {
  const resolvedRuntime: Required<CliRuntime> = {
    cwd: runtime.cwd ?? defaultRuntime.cwd,
    writeStdout: runtime.writeStdout ?? defaultRuntime.writeStdout,
    writeStderr: runtime.writeStderr ?? defaultRuntime.writeStderr,
  };

  if (args.length === 0 || args[0] === 'help' || args[0] === '--help') {
    resolvedRuntime.writeStdout(renderHelpMessage());
    return 0;
  }

  if (args[0] === 'check') {
    const parsed = parseArguments(args.slice(1));

    if ('code' in parsed) {
      resolvedRuntime.writeStderr(formatDiagnosticsForTerminal([parsed]));
      return 1;
    }

    if (parsed.help) {
      resolvedRuntime.writeStdout(renderHelpMessage());
      return 0;
    }

    if (parsed.positionals.length > 1) {
      resolvedRuntime.writeStderr(
        'The `check` command no longer accepts a rules glob. Create `.critiq/config.yaml` and run `critiq check .`.',
      );
      return 1;
    }

    if (
      parsed.positionals.length === 1 &&
      isLegacyRulesArgument(parsed.positionals[0])
    ) {
      resolvedRuntime.writeStderr(
        'The `check` command no longer accepts a rules glob. Create `.critiq/config.yaml` and run `critiq check .`.',
      );
      return 1;
    }

    return handleCheck(
      parsed.positionals[0],
      parsed.format,
      resolvedRuntime,
      parsed.baseRef,
      parsed.headRef,
    );
  }

  if (args[0] !== 'rules') {
    resolvedRuntime.writeStderr(`Unknown command: ${args[0]}`);
    resolvedRuntime.writeStdout(renderHelpMessage());
    return 1;
  }

  const subcommand = args[1];
  const parsed = parseArguments(args.slice(2));

  if (subcommand === 'help' || subcommand === '--help') {
    resolvedRuntime.writeStdout(renderHelpMessage());
    return 0;
  }

  if ('code' in parsed) {
    resolvedRuntime.writeStderr(formatDiagnosticsForTerminal([parsed]));
    return 1;
  }

  if (parsed.help || !subcommand) {
    resolvedRuntime.writeStdout(renderHelpMessage());
    return 0;
  }

  if (subcommand === 'validate') {
    if (parsed.positionals.length !== 1) {
      resolvedRuntime.writeStderr(
        'Expected `critiq rules validate <glob>` with exactly one target.',
      );
      return 1;
    }

    return handleValidate(
      parsed.positionals[0],
      parsed.format,
      resolvedRuntime,
    );
  }

  if (subcommand === 'test') {
    if (parsed.positionals.length > 1) {
      resolvedRuntime.writeStderr(
        'Expected `critiq rules test [glob]` with zero or one target.',
      );
      return 1;
    }

    return handleTest(parsed.positionals[0], parsed.format, resolvedRuntime);
  }

  if (subcommand === 'normalize') {
    if (parsed.positionals.length !== 1) {
      resolvedRuntime.writeStderr(
        'Expected `critiq rules normalize <file>` with exactly one file.',
      );
      return 1;
    }

    return handleNormalizeOrExplain(
      'normalize',
      parsed.positionals[0],
      parsed.format,
      resolvedRuntime,
    );
  }

  if (subcommand === 'explain') {
    if (parsed.positionals.length !== 1) {
      resolvedRuntime.writeStderr(
        'Expected `critiq rules explain <file>` with exactly one file.',
      );
      return 1;
    }

    return handleNormalizeOrExplain(
      'explain',
      parsed.positionals[0],
      parsed.format,
      resolvedRuntime,
    );
  }

  resolvedRuntime.writeStderr(`Unknown command: rules ${subcommand}`);
  resolvedRuntime.writeStdout(renderHelpMessage());
  return 1;
}

function isCliEntrypoint(): boolean {
  if (require.main === module) {
    return true;
  }

  const mainFilename = require.main?.filename;

  if (!mainFilename) {
    return false;
  }

  // Nx emits a root wrapper at dist/apps/cli/main.js that requires the real
  // compiled CLI module from dist/apps/cli/apps/cli/src/main.js.
  return mainFilename === resolve(__dirname, '..', '..', '..', 'main.js');
}

if (isCliEntrypoint()) {
  process.exitCode = runCli();
}
