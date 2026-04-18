import { typescriptSourceAdapter } from '@critiq/adapter-typescript';
import {
  detectRepositoryLanguages,
  filterNormalizedRulesForCatalog,
  loadRuleCatalogFile,
  resolveCatalogPackage,
  resolveCatalogRulePaths,
} from '@critiq/core-catalog';
import { loadCritiqConfigForDirectory } from '@critiq/core-config';
import {
  aggregateDiagnostics,
  createDiagnostic,
  type Diagnostic,
} from '@critiq/core-diagnostics';
import type {
  FindingSeverity,
  FindingV0,
} from '@critiq/core-finding-schema';
import { normalizeRuleDocument, type NormalizedRule } from '@critiq/core-ir';
import {
  loadRuleFile,
  validateLoadedRuleDocumentContract,
  validateRuleDocumentSemantics,
} from '@critiq/core-rules-dsl';
import {
  buildFinding,
  evaluateRule,
  evaluateRuleApplicability,
  type AnalyzedFile,
  type DiffRange,
} from '@critiq/core-rules-engine';
import { minimatch } from 'minimatch';
import { execFileSync } from 'node:child_process';
import {
  existsSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
} from 'node:fs';
import { dirname, extname, isAbsolute, relative, resolve, sep } from 'node:path';

const DEFAULT_CATALOG_PACKAGE_NAME = '@critiq/rules' as const;
const RULE_CATALOG_FILENAME = 'catalog.yaml' as const;

export interface SourceAdapterAnalysisSuccess {
  success: true;
  data: AnalyzedFile;
}

export interface SourceAdapterAnalysisFailure {
  success: false;
  diagnostics: Diagnostic[];
}

export type SourceAdapterAnalysisResult =
  | SourceAdapterAnalysisSuccess
  | SourceAdapterAnalysisFailure;

export interface SourceAdapter {
  packageName: string;
  supportedExtensions: readonly string[];
  analyze(path: string, text: string): SourceAdapterAnalysisResult;
}

export interface SourceAdapterRegistry {
  adapters: readonly SourceAdapter[];
  findAdapterForPath(path: string): SourceAdapter | undefined;
  supportedExtensions(): string[];
}

export interface CheckRuleSummary {
  ruleId: string;
  findingCount: number;
  severityCounts: Record<FindingSeverity, number>;
}

export interface CheckOverallRuleResult {
  ruleId: string;
  status: 'passed' | 'failed';
}

export interface CheckCommandScopeRepo {
  mode: 'repo';
}

export interface CheckCommandScopeDiff {
  mode: 'diff';
  base: string;
  head: string;
  changedFileCount: number;
}

export type CheckCommandScope = CheckCommandScopeRepo | CheckCommandScopeDiff;

export interface CheckCommandEnvelope {
  command: 'check';
  format: 'pretty' | 'json';
  exitCode: number;
  target: string;
  catalogPackage: string | null;
  preset: 'recommended' | 'strict' | 'security' | 'experimental' | null;
  scope: CheckCommandScope;
  scannedFileCount: number;
  matchedRuleCount: number;
  findingCount: number;
  findings: FindingV0[];
  ruleSummaries: CheckRuleSummary[];
  diagnostics: Diagnostic[];
}

interface CheckResolvedTarget {
  absolutePath: string;
  isDirectory: boolean;
  displayRoot: string;
  repoRoot?: string;
}

interface CheckResolvedScope {
  scope: CheckCommandScope;
  files: string[];
  changedRangesByAbsolutePath: Map<string, DiffRange[]>;
}

export interface RunCheckCommandOptions {
  cwd?: string;
  target?: string;
  format?: 'pretty' | 'json';
  baseRef?: string;
  headRef?: string;
  defaultCatalogPackage?: string;
  catalogPackageRoots?: Record<string, string>;
  catalogResolverBasePaths?: readonly string[];
  adapterRegistry?: SourceAdapterRegistry;
}

export interface RunCheckCommandResult {
  envelope: CheckCommandEnvelope;
  overallRuleResults: CheckOverallRuleResult[];
  sourceTextsByPath: ReadonlyMap<string, string>;
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

function hasGlobMagic(value: string): boolean {
  return /[*?[\]{}]/.test(value);
}

function determineExitCode(diagnostics: readonly Diagnostic[]): number {
  if (
    diagnostics.some(
      (diagnostic) => diagnostic.code === 'runtime.internal.error',
    )
  ) {
    return 2;
  }

  if (diagnostics.some((diagnostic) => diagnostic.severity === 'error')) {
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

function createCheckRuntimeDiagnostic(
  code: string,
  message: string,
  details?: Record<string, unknown>,
): Diagnostic {
  return createDiagnostic({
    code,
    message,
    details,
  });
}

function readTextFileSafe(
  path: string,
):
  | { success: true; text: string }
  | { success: false; diagnostics: Diagnostic[] } {
  try {
    return {
      success: true,
      text: readFileSync(path, 'utf8'),
    };
  } catch (error) {
    return {
      success: false,
      diagnostics: [
        createCheckRuntimeDiagnostic(
          'runtime.internal.error',
          error instanceof Error
            ? error.message
            : 'Unexpected source file read failure.',
          {
            path,
          },
        ),
      ],
    };
  }
}

function loadNormalizedRulesForCatalog(
  absoluteRulePaths: readonly string[],
): { success: true; rules: NormalizedRule[]; diagnostics: Diagnostic[] } | { success: false; rules: NormalizedRule[]; diagnostics: Diagnostic[] } {
  const rules: NormalizedRule[] = [];
  const diagnostics: Diagnostic[] = [];

  for (const absolutePath of [...absoluteRulePaths].sort((left, right) =>
    left.localeCompare(right),
  )) {
    const loadResult = loadRuleFile(absolutePath);

    if (!loadResult.success) {
      const failure = loadResult as Extract<typeof loadResult, { success: false }>;
      diagnostics.push(...failure.diagnostics);
      continue;
    }

    const contractValidation = validateLoadedRuleDocumentContract(loadResult.data);

    if (!contractValidation.success) {
      const failure = contractValidation as Extract<
        typeof contractValidation,
        { success: false }
      >;
      diagnostics.push(...failure.diagnostics);
      continue;
    }

    const semanticValidation = validateRuleDocumentSemantics(contractValidation.data);

    if (!semanticValidation.success) {
      diagnostics.push(...semanticValidation.diagnostics);
      continue;
    }

    rules.push(normalizeRuleDocument(contractValidation.data).rule);
  }

  const aggregatedDiagnostics = aggregateDiagnostics(diagnostics);

  if (aggregatedDiagnostics.length > 0) {
    return {
      success: false,
      rules,
      diagnostics: aggregatedDiagnostics,
    };
  }

  return {
    success: true,
    rules,
    diagnostics: [],
  };
}

function normalizeExtension(value: string): string {
  const normalized = value.toLowerCase();

  return normalized.startsWith('.') ? normalized : `.${normalized}`;
}

function defaultCatalogPackageRootsFromEnvironment(): Record<string, string> {
  const rulesRoot = process.env['CRITIQ_RULES_ROOT']?.trim();

  if (!rulesRoot) {
    return {};
  }

  const directRoot = resolve(rulesRoot);
  const candidateRoots = [
    directRoot,
    resolve(directRoot, 'libs/rules/catalog'),
  ];

  for (const candidateRoot of candidateRoots) {
    if (existsSync(resolve(candidateRoot, RULE_CATALOG_FILENAME))) {
      return {
        [DEFAULT_CATALOG_PACKAGE_NAME]: candidateRoot,
      };
    }
  }

  return {};
}

function resolveCatalogPackageForRuntime(
  displayRoot: string,
  packageName: string,
  options: RunCheckCommandOptions,
) {
  const packageRootOverrides = {
    ...defaultCatalogPackageRootsFromEnvironment(),
    ...(options.catalogPackageRoots ?? {}),
  };
  const packageRootOverride = packageRootOverrides[packageName];

  if (
    packageRootOverride &&
    existsSync(resolve(packageRootOverride, RULE_CATALOG_FILENAME))
  ) {
    return {
      success: true as const,
      data: {
        packageName,
        packageRoot: packageRootOverride,
        entryPath: resolve(packageRootOverride, 'package.json'),
        catalogPath: resolve(packageRootOverride, RULE_CATALOG_FILENAME),
      },
    };
  }

  return resolveCatalogPackage(displayRoot, packageName, [
    ...(options.catalogResolverBasePaths ?? []),
  ]);
}

function isPathWithinDirectory(
  directoryPath: string,
  candidatePath: string,
): boolean {
  const relativePath = relative(directoryPath, candidatePath);

  return (
    relativePath.length === 0 ||
    (!relativePath.startsWith('..') && !isAbsolute(relativePath))
  );
}

function tryResolveGitRepoRoot(workingDirectory: string): string | undefined {
  try {
    return toPosixPath(
      execFileSync('git', ['rev-parse', '--show-toplevel'], {
        cwd: workingDirectory,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim(),
    );
  } catch {
    return undefined;
  }
}

function resolveCheckTarget(
  cwd: string,
  target: string | undefined,
):
  | { success: true; data: CheckResolvedTarget }
  | { success: false; diagnostics: Diagnostic[] } {
  const resolvedTarget = target ?? '.';

  if (hasGlobMagic(resolvedTarget)) {
    return {
      success: false,
      diagnostics: [
        createDiagnostic({
          code: 'cli.input.invalid',
          message: `Expected a concrete path for \`${resolvedTarget}\`, not a glob.`,
        }),
      ],
    };
  }

  const candidatePath = resolve(cwd, resolvedTarget);

  try {
    const absolutePath = toPosixPath(realpathSync(candidatePath));
    const stats = statSync(absolutePath);

    if (!stats.isDirectory() && !stats.isFile()) {
      return {
        success: false,
        diagnostics: [
          createDiagnostic({
            code: 'cli.input.invalid',
            message: `Expected \`${resolvedTarget}\` to be a file or directory.`,
          }),
        ],
      };
    }

    const scopeDirectory = stats.isDirectory()
      ? absolutePath
      : dirname(absolutePath);
    const repoRoot = tryResolveGitRepoRoot(scopeDirectory);

    return {
      success: true,
      data: {
        absolutePath,
        isDirectory: stats.isDirectory(),
        displayRoot: repoRoot ?? scopeDirectory,
        repoRoot,
      },
    };
  } catch {
    return {
      success: false,
      diagnostics: [
        createDiagnostic({
          code: 'cli.input.invalid',
          message: `No files matched \`${resolvedTarget}\`.`,
          details: {
            target: resolvedTarget,
          },
        }),
      ],
    };
  }
}

function parseChangedRange(
  startLineText: string,
  countText: string | undefined,
): DiffRange | null {
  const startLine = Number.parseInt(startLineText, 10);
  const count = countText ? Number.parseInt(countText, 10) : 1;

  if (!Number.isInteger(startLine) || !Number.isInteger(count) || count <= 0) {
    return null;
  }

  return {
    startLine,
    startColumn: 1,
    endLine: startLine + count - 1,
    endColumn: Number.MAX_SAFE_INTEGER,
  };
}

function normalizeGitDiffPath(value: string): string | null {
  if (value === '/dev/null') {
    return null;
  }

  if (value.startsWith('b/')) {
    return value.slice(2);
  }

  return value;
}

function parseGitDiffChangedRanges(output: string): Map<string, DiffRange[]> {
  const changedRanges = new Map<string, DiffRange[]>();
  let currentPath: string | null = null;

  for (const line of output.split(/\r?\n/)) {
    if (line.startsWith('+++ ')) {
      currentPath = normalizeGitDiffPath(line.slice(4));

      if (currentPath && !changedRanges.has(currentPath)) {
        changedRanges.set(currentPath, []);
      }

      continue;
    }

    if (!currentPath || !line.startsWith('@@ ')) {
      continue;
    }

    const match = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);

    if (!match) {
      continue;
    }

    const changedRange = parseChangedRange(match[1], match[2]);

    if (!changedRange) {
      continue;
    }

    changedRanges.set(currentPath, [
      ...(changedRanges.get(currentPath) ?? []),
      changedRange,
    ]);
  }

  return changedRanges;
}

function runGitCommand(
  cwd: string,
  args: string[],
):
  | { success: true; stdout: string }
  | { success: false; diagnostics: Diagnostic[] } {
  try {
    return {
      success: true,
      stdout: execFileSync('git', args, {
        cwd,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    };
  } catch (error) {
    return {
      success: false,
      diagnostics: [
        createCheckRuntimeDiagnostic(
          'cli.git.command.failed',
          error instanceof Error
            ? error.message
            : 'Unexpected git command failure.',
          {
            args,
          },
        ),
      ],
    };
  }
}

function resolveCheckScope(
  target: CheckResolvedTarget,
  baseRef: string | undefined,
  headRef: string | undefined,
  registry: SourceAdapterRegistry,
):
  | { success: true; data: CheckResolvedScope }
  | { success: false; diagnostics: Diagnostic[] } {
  if ((baseRef && !headRef) || (!baseRef && headRef)) {
    return {
      success: false,
      diagnostics: [
        createCheckRuntimeDiagnostic(
          'cli.argument.invalid',
          'Expected `--base` and `--head` to be provided together.',
        ),
      ],
    };
  }

  if (!baseRef && !headRef) {
    const files = target.isDirectory
      ? walkFiles(target.absolutePath).filter((path) =>
          Boolean(registry.findAdapterForPath(path)),
        )
      : registry.findAdapterForPath(target.absolutePath)
        ? [target.absolutePath]
        : [];

    return {
      success: true,
      data: {
        scope: {
          mode: 'repo',
        },
        files,
        changedRangesByAbsolutePath: new Map<string, DiffRange[]>(),
      },
    };
  }

  if (!target.repoRoot) {
    return {
      success: false,
      diagnostics: [
        createCheckRuntimeDiagnostic(
          'cli.git.not-repository',
          'Diff mode requires the target path to be inside a git repository.',
          {
            target: target.absolutePath,
          },
        ),
      ],
    };
  }

  const changedFilesResult = runGitCommand(target.repoRoot, [
    'diff',
    '--name-only',
    baseRef as string,
    headRef as string,
    '--',
  ]);

  if (!changedFilesResult.success) {
    const failure = changedFilesResult as Extract<
      typeof changedFilesResult,
      { success: false }
    >;

    return {
      success: false,
      diagnostics: failure.diagnostics,
    };
  }

  const diffResult = runGitCommand(target.repoRoot, [
    'diff',
    '--no-color',
    '--no-ext-diff',
    '--unified=0',
    baseRef as string,
    headRef as string,
    '--',
  ]);

  if (!diffResult.success) {
    const failure = diffResult as Extract<typeof diffResult, { success: false }>;

    return {
      success: false,
      diagnostics: failure.diagnostics,
    };
  }

  const changedRangesByRelativePath = parseGitDiffChangedRanges(diffResult.stdout);
  const files = changedFilesResult.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => resolve(target.repoRoot as string, line))
    .filter(
      (absolutePath) =>
        Boolean(registry.findAdapterForPath(absolutePath)) &&
        (target.isDirectory
          ? isPathWithinDirectory(target.absolutePath, absolutePath)
          : resolve(absolutePath) === target.absolutePath),
    )
    .filter((absolutePath) => {
      try {
        return statSync(absolutePath).isFile();
      } catch {
        return false;
      }
    })
    .sort((left, right) => left.localeCompare(right));
  const changedRangesByAbsolutePath = new Map<string, DiffRange[]>();

  for (const absolutePath of files) {
    const relativePath = toPosixPath(relative(target.repoRoot, absolutePath));
    changedRangesByAbsolutePath.set(
      absolutePath,
      changedRangesByRelativePath.get(relativePath) ?? [],
    );
  }

  return {
    success: true,
    data: {
      scope: {
        mode: 'diff',
        base: baseRef as string,
        head: headRef as string,
        changedFileCount: files.length,
      },
      files,
      changedRangesByAbsolutePath,
    },
  };
}

function filterIgnoredPaths(
  files: readonly string[],
  changedRangesByAbsolutePath: ReadonlyMap<string, DiffRange[]>,
  displayRoot: string,
  ignorePaths: readonly string[],
): { files: string[]; changedRangesByAbsolutePath: Map<string, DiffRange[]> } {
  const nextFiles = files.filter((absolutePath) => {
    const displayPath = toDisplayPath(displayRoot, absolutePath);

    return !ignorePaths.some((pattern) =>
      minimatch(displayPath, pattern, { dot: true }),
    );
  });

  return {
    files: nextFiles,
    changedRangesByAbsolutePath: new Map(
      nextFiles.map((absolutePath) => [
        absolutePath,
        changedRangesByAbsolutePath.get(absolutePath) ?? [],
      ]),
    ),
  };
}

function applySeverityOverride(
  finding: FindingV0,
  severityOverride: FindingV0['severity'] | undefined,
): FindingV0 {
  if (!severityOverride || severityOverride === finding.severity) {
    return finding;
  }

  return {
    ...finding,
    severity: severityOverride,
  };
}

function compareFindings(left: FindingV0, right: FindingV0): number {
  const leftLocation = left.locations.primary;
  const rightLocation = right.locations.primary;

  return (
    leftLocation.path.localeCompare(rightLocation.path) ||
    leftLocation.startLine - rightLocation.startLine ||
    leftLocation.startColumn - rightLocation.startColumn ||
    leftLocation.endLine - rightLocation.endLine ||
    leftLocation.endColumn - rightLocation.endColumn ||
    left.rule.id.localeCompare(right.rule.id) ||
    left.fingerprints.primary.localeCompare(right.fingerprints.primary)
  );
}

function summarizeFindings(findings: readonly FindingV0[]): CheckRuleSummary[] {
  const summaries = new Map<string, CheckRuleSummary>();

  for (const finding of findings) {
    const summary = summaries.get(finding.rule.id) ?? {
      ruleId: finding.rule.id,
      findingCount: 0,
      severityCounts: {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
      },
    };

    summary.findingCount += 1;
    summary.severityCounts[finding.severity] += 1;
    summaries.set(finding.rule.id, summary);
  }

  return Array.from(summaries.values()).sort((left, right) =>
    left.ruleId.localeCompare(right.ruleId),
  );
}

export function createSourceAdapterRegistry(
  adapters: readonly SourceAdapter[],
): SourceAdapterRegistry {
  const normalizedAdapters = [...adapters].map((adapter) => ({
    ...adapter,
    supportedExtensions: adapter.supportedExtensions.map(normalizeExtension),
  }));

  return {
    adapters: normalizedAdapters,
    findAdapterForPath(path: string) {
      const extension = normalizeExtension(extname(path));

      return normalizedAdapters.find((adapter) =>
        adapter.supportedExtensions.includes(extension),
      );
    },
    supportedExtensions() {
      return Array.from(
        new Set(
          normalizedAdapters.flatMap((adapter) => adapter.supportedExtensions),
        ),
      ).sort((left, right) => left.localeCompare(right));
    },
  };
}

export function createDefaultSourceAdapterRegistry(): SourceAdapterRegistry {
  return createSourceAdapterRegistry([typescriptSourceAdapter]);
}

export function runCheckCommand(
  options: RunCheckCommandOptions = {},
): RunCheckCommandResult {
  const cwd = options.cwd ?? process.cwd();
  const format = options.format ?? 'pretty';
  const target = options.target ?? '.';
  const registry =
    options.adapterRegistry ?? createDefaultSourceAdapterRegistry();
  const resolvedTarget = resolveCheckTarget(cwd, target);

  if (!resolvedTarget.success) {
    const failure = resolvedTarget as Extract<
      typeof resolvedTarget,
      { success: false }
    >;
    const diagnostics = aggregateDiagnostics(failure.diagnostics);
    return {
      envelope: {
        command: 'check',
        format,
        target,
        catalogPackage: null,
        preset: null,
        scope:
          options.baseRef && options.headRef
            ? {
                mode: 'diff',
                base: options.baseRef,
                head: options.headRef,
                changedFileCount: 0,
              }
            : {
                mode: 'repo',
              },
        scannedFileCount: 0,
        matchedRuleCount: 0,
        findingCount: 0,
        findings: [],
        ruleSummaries: [],
        diagnostics,
        exitCode: determineExitCode(diagnostics) || 1,
      },
      overallRuleResults: [],
      sourceTextsByPath: new Map<string, string>(),
    };
  }

  const loadedConfig = loadCritiqConfigForDirectory(
    resolvedTarget.data.displayRoot,
  );

  if (!loadedConfig.success) {
    const failure = loadedConfig as Extract<typeof loadedConfig, { success: false }>;
    return {
      envelope: {
        command: 'check',
        format,
        target,
        catalogPackage: null,
        preset: null,
        scope:
          options.baseRef && options.headRef
            ? {
                mode: 'diff',
                base: options.baseRef,
                head: options.headRef,
                changedFileCount: 0,
              }
            : {
                mode: 'repo',
              },
        scannedFileCount: 0,
        matchedRuleCount: 0,
        findingCount: 0,
        findings: [],
        ruleSummaries: [],
        diagnostics: failure.diagnostics,
        exitCode: determineExitCode(failure.diagnostics) || 1,
      },
      overallRuleResults: [],
      sourceTextsByPath: new Map<string, string>(),
    };
  }

  const catalogPackageName =
    loadedConfig.data.catalogPackage ??
    options.defaultCatalogPackage ??
    DEFAULT_CATALOG_PACKAGE_NAME;
  const resolvedCatalogPackage = resolveCatalogPackageForRuntime(
    resolvedTarget.data.displayRoot,
    catalogPackageName,
    options,
  );

  if (!resolvedCatalogPackage.success) {
    const failure = resolvedCatalogPackage as Extract<
      typeof resolvedCatalogPackage,
      { success: false }
    >;
    return {
      envelope: {
        command: 'check',
        format,
        target,
        catalogPackage: catalogPackageName,
        preset: loadedConfig.data.preset,
        scope:
          options.baseRef && options.headRef
            ? {
                mode: 'diff',
                base: options.baseRef,
                head: options.headRef,
                changedFileCount: 0,
              }
            : {
                mode: 'repo',
              },
        scannedFileCount: 0,
        matchedRuleCount: 0,
        findingCount: 0,
        findings: [],
        ruleSummaries: [],
        diagnostics: failure.diagnostics,
        exitCode: determineExitCode(failure.diagnostics) || 1,
      },
      overallRuleResults: [],
      sourceTextsByPath: new Map<string, string>(),
    };
  }

  const loadedCatalog = loadRuleCatalogFile(resolvedCatalogPackage.data.catalogPath);

  if (!loadedCatalog.success) {
    const failure = loadedCatalog as Extract<typeof loadedCatalog, { success: false }>;
    return {
      envelope: {
        command: 'check',
        format,
        target,
        catalogPackage: catalogPackageName,
        preset: loadedConfig.data.preset,
        scope:
          options.baseRef && options.headRef
            ? {
                mode: 'diff',
                base: options.baseRef,
                head: options.headRef,
                changedFileCount: 0,
              }
            : {
                mode: 'repo',
              },
        scannedFileCount: 0,
        matchedRuleCount: 0,
        findingCount: 0,
        findings: [],
        ruleSummaries: [],
        diagnostics: failure.diagnostics,
        exitCode: determineExitCode(failure.diagnostics) || 1,
      },
      overallRuleResults: [],
      sourceTextsByPath: new Map<string, string>(),
    };
  }

  const catalogRuleEntries = resolveCatalogRulePaths(
    loadedCatalog.data,
    resolvedCatalogPackage.data.packageRoot,
    loadedConfig.data.preset,
  );
  const loadedRules = loadNormalizedRulesForCatalog(
    catalogRuleEntries.map((entry) => entry.rulePath),
  );

  if (!loadedRules.success) {
    return {
      envelope: {
        command: 'check',
        format,
        target,
        catalogPackage: catalogPackageName,
        preset: loadedConfig.data.preset,
        scope:
          options.baseRef && options.headRef
            ? {
                mode: 'diff',
                base: options.baseRef,
                head: options.headRef,
                changedFileCount: 0,
              }
            : {
                mode: 'repo',
              },
        scannedFileCount: 0,
        matchedRuleCount: loadedRules.rules.length,
        findingCount: 0,
        findings: [],
        ruleSummaries: [],
        diagnostics: loadedRules.diagnostics,
        exitCode: determineExitCode(loadedRules.diagnostics) || 1,
      },
      overallRuleResults: [],
      sourceTextsByPath: new Map<string, string>(),
    };
  }

  const resolvedScope = resolveCheckScope(
    resolvedTarget.data,
    options.baseRef,
    options.headRef,
    registry,
  );

  if (!resolvedScope.success) {
    const failure = resolvedScope as Extract<
      typeof resolvedScope,
      { success: false }
    >;
    const diagnostics = aggregateDiagnostics(failure.diagnostics);

    return {
      envelope: {
        command: 'check',
        format,
        target,
        catalogPackage: catalogPackageName,
        preset: loadedConfig.data.preset,
        scope:
          options.baseRef && options.headRef
            ? {
                mode: 'diff',
                base: options.baseRef,
                head: options.headRef,
                changedFileCount: 0,
              }
            : {
                mode: 'repo',
              },
        scannedFileCount: 0,
        matchedRuleCount: loadedRules.rules.length,
        findingCount: 0,
        findings: [],
        ruleSummaries: [],
        diagnostics,
        exitCode: determineExitCode(diagnostics) || 1,
      },
      overallRuleResults: [],
      sourceTextsByPath: new Map<string, string>(),
    };
  }

  const filteredScope = filterIgnoredPaths(
    resolvedScope.data.files,
    resolvedScope.data.changedRangesByAbsolutePath,
    resolvedTarget.data.displayRoot,
    loadedConfig.data.ignorePaths,
  );
  const detectedLanguages = detectRepositoryLanguages(filteredScope.files);
  const activeRules = filterNormalizedRulesForCatalog(
    loadedRules.rules,
    {
      ...loadedConfig.data,
      catalogPackage: catalogPackageName,
    },
    detectedLanguages,
  );
  const informationalDiagnostics: Diagnostic[] = [];

  if (detectedLanguages.length === 0) {
    informationalDiagnostics.push(
      createDiagnostic({
        code: 'catalog.repo.no-supported-languages',
        severity: 'info',
        message:
          'No supported source files were detected after applying ignore paths.',
      }),
    );
  } else if (activeRules.length === 0) {
    informationalDiagnostics.push(
      createDiagnostic({
        code: 'catalog.rules.none-active',
        severity: 'info',
        message:
          'No catalog rules remained active after preset selection, repository language detection, and config filters.',
      }),
    );
  }

  const findings: FindingV0[] = [];
  const diagnostics: Diagnostic[] = [...informationalDiagnostics];
  const seenFingerprints = new Set<string>();
  const sourceTextsByPath = new Map<string, string>();

  for (const absolutePath of filteredScope.files) {
    const textResult = readTextFileSafe(absolutePath);

    if (!textResult.success) {
      const failure = textResult as Extract<typeof textResult, { success: false }>;
      diagnostics.push(...failure.diagnostics);
      continue;
    }

    const displayPath = toDisplayPath(
      resolvedTarget.data.displayRoot,
      absolutePath,
    );
    sourceTextsByPath.set(displayPath, textResult.text);

    const adapter = registry.findAdapterForPath(displayPath);

    if (!adapter) {
      diagnostics.push(
        createCheckRuntimeDiagnostic(
          'catalog.repo.no-adapter',
          `No source adapter is registered for \`${displayPath}\`.`,
        ),
      );
      continue;
    }

    const analysis = adapter.analyze(displayPath, textResult.text);

    if (!analysis.success) {
      const failure = analysis as Extract<typeof analysis, { success: false }>;
      diagnostics.push(...failure.diagnostics);
      continue;
    }

    const analyzedFile = {
      ...analysis.data,
      changedRanges: filteredScope.changedRangesByAbsolutePath.get(absolutePath),
    };

    for (const rule of activeRules) {
      const applicability = evaluateRuleApplicability(rule, analyzedFile);

      if (!applicability.applicable) {
        continue;
      }

      for (const match of evaluateRule(rule, analyzedFile)) {
        const buildResult = buildFinding(rule, analyzedFile, match, {
          engineKind: 'critiq-cli',
          rulePack: catalogPackageName,
        });

        if (!buildResult.success) {
          const failure = buildResult as Extract<
            typeof buildResult,
            { success: false }
          >;
          diagnostics.push(
            ...failure.issues.map((issue) =>
              createCheckRuntimeDiagnostic(
                issue.code,
                issue.message,
                issue.details,
              ),
            ),
          );
          continue;
        }

        if (seenFingerprints.has(buildResult.finding.fingerprints.primary)) {
          continue;
        }

        seenFingerprints.add(buildResult.finding.fingerprints.primary);
        findings.push(
          applySeverityOverride(
            buildResult.finding,
            loadedConfig.data.severityOverrides[buildResult.finding.rule.id],
          ),
        );
      }
    }
  }

  const aggregatedDiagnostics = aggregateDiagnostics(diagnostics);
  const sortedFindings = [...findings].sort(compareFindings);
  const ruleSummaries = summarizeFindings(sortedFindings);
  const exitCode =
    aggregatedDiagnostics.length > 0
      ? determineExitCode(aggregatedDiagnostics)
      : sortedFindings.length > 0
        ? 1
        : 0;
  const overallRuleResults: CheckOverallRuleResult[] = activeRules
    .map((rule) => ({
      ruleId: rule.ruleId,
      status: sortedFindings.some((finding) => finding.rule.id === rule.ruleId)
        ? ('failed' as const)
        : ('passed' as const),
    }))
    .sort((left, right) => left.ruleId.localeCompare(right.ruleId));

  return {
    envelope: {
      command: 'check',
      format,
      exitCode,
      target,
      catalogPackage: catalogPackageName,
      preset: loadedConfig.data.preset,
      scope:
        resolvedScope.data.scope.mode === 'diff'
          ? {
              ...resolvedScope.data.scope,
              changedFileCount: filteredScope.files.length,
            }
          : resolvedScope.data.scope,
      scannedFileCount: filteredScope.files.length,
      matchedRuleCount: activeRules.length,
      findingCount: sortedFindings.length,
      findings: sortedFindings,
      ruleSummaries,
      diagnostics: aggregatedDiagnostics,
    },
    overallRuleResults,
    sourceTextsByPath,
  };
}
