import {
  aggregateDiagnostics,
  createDiagnostic,
  type Diagnostic,
} from '@critiq/core-diagnostics';
import type {
  FindingProvenance,
  FindingSeverity,
  FindingV0,
} from '@critiq/core-finding-schema';
import {
  normalizeRuleDocument,
  type CanonicalLanguage,
  type NormalizedRule,
} from '@critiq/core-ir';
import {
  loadRuleFile,
  validateLoadedRuleDocumentContract,
  validateRuleDocumentSemantics,
} from '@critiq/core-rules-dsl';
import type { AnalyzedFile, DiffRange } from '@critiq/core-rules-engine';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

export const DEFAULT_CATALOG_PACKAGE_NAME = '@critiq/rules' as const;
export const RULE_CATALOG_FILENAME = 'catalog.yaml' as const;

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
  supportedLanguages: readonly CanonicalLanguage[];
  analyze(path: string, text: string): SourceAdapterAnalysisResult;
}

export interface SourceAdapterRegistry {
  adapters: readonly SourceAdapter[];
  findAdapterForPath(path: string): SourceAdapter | undefined;
  hasAdapterForLanguage(language: CanonicalLanguage): boolean;
  supportedExtensions(): string[];
  supportedLanguages(): CanonicalLanguage[];
}

export interface CheckRuleSummary {
  ruleId: string;
  findingCount: number;
  severityCounts: Record<FindingSeverity, number>;
}

export interface CheckReportFindingAttributes {
  detail?: string;
}

export interface CheckReportFinding
  extends Omit<FindingV0, 'provenance' | 'fingerprints' | 'attributes'> {
  fingerprints: {
    primary: FindingV0['fingerprints']['primary'];
  };
  attributes?: CheckReportFindingAttributes;
}

export type CheckCommandProvenance = FindingProvenance;

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

export interface CheckSecretsScanFindingLocation {
  path: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

export interface CheckSecretsScanFinding {
  detectorId: string;
  summary: string;
  fingerprint: string;
  locations: {
    primary: CheckSecretsScanFindingLocation;
  };
}

export interface CheckSecretsScanPayload {
  scope: CheckCommandScope;
  scannedFileCount: number;
  findingCount: number;
  findings: CheckSecretsScanFinding[];
  diagnostics: Diagnostic[];
}

export interface CheckCommandEnvelope {
  command: 'check';
  format: 'pretty' | 'json';
  exitCode: number;
  target: string;
  catalogPackage: string | null;
  preset: 'recommended' | 'strict' | 'security' | 'experimental' | null;
  scope: CheckCommandScope;
  provenance: CheckCommandProvenance;
  scannedFileCount: number;
  matchedRuleCount: number;
  findingCount: number;
  findings: CheckReportFinding[];
  ruleSummaries: CheckRuleSummary[];
  diagnostics: Diagnostic[];
  secretsScan?: CheckSecretsScanPayload;
}

export interface CheckResolvedTarget {
  absolutePath: string;
  isDirectory: boolean;
  displayRoot: string;
  repoRoot?: string;
}

export interface CheckResolvedScope {
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
  onProgress?: (update: CheckProgressUpdate) => void;
}

export interface CheckProgressUpdate {
  step: 'preparing' | 'scanning' | 'finalizing';
  scannedFileCount: number;
  totalFileCount: number;
  currentFilePath?: string;
}

export interface RunCheckCommandResult {
  envelope: CheckCommandEnvelope;
  overallRuleResults: CheckOverallRuleResult[];
  sourceTextsByPath: ReadonlyMap<string, string>;
}

export function toPosixPath(value: string): string {
  return value.split(sep).join('/');
}

export function toDisplayPath(cwd: string, absolutePath: string): string {
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

export function hasGlobMagic(value: string): boolean {
  return /[*?[\]{}]/.test(value);
}

export function determineExitCode(diagnostics: readonly Diagnostic[]): number {
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

function isSkippableDirectory(
  currentDirectory: string,
  name: string,
): boolean {
  if (
    ['.git', '.nx', '.serverless', 'cdk.out', 'coverage', 'dist', 'node_modules', 'vendor'].includes(
      name,
    )
  ) {
    return true;
  }

  return name === 'cache' && currentDirectory.split(sep).at(-1) === '.yarn';
}

export function walkFiles(rootDirectory: string): string[] {
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
        if (!isSkippableDirectory(currentDirectory, entry.name)) {
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

export function createCheckRuntimeDiagnostic(
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

export function readTextFileSafe(
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

export function loadNormalizedRulesForCatalog(
  absoluteRulePaths: readonly string[],
):
  | { success: true; rules: NormalizedRule[]; diagnostics: Diagnostic[] }
  | { success: false; rules: NormalizedRule[]; diagnostics: Diagnostic[] } {
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

    const contractValidation = validateLoadedRuleDocumentContract(
      loadResult.data,
    );

    if (!contractValidation.success) {
      const failure = contractValidation as Extract<
        typeof contractValidation,
        { success: false }
      >;
      diagnostics.push(...failure.diagnostics);
      continue;
    }

    const semanticValidation = validateRuleDocumentSemantics(
      contractValidation.data,
    );

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

export function normalizeExtension(value: string): string {
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

export function resolveCatalogPackageForRuntime(
  _displayRoot: string,
  packageName: string,
  options: RunCheckCommandOptions,
) {
  const packageRootOverrides = {
    ...defaultCatalogPackageRootsFromEnvironment(),
    ...(options.catalogPackageRoots ?? {}),
  };

  return {
    packageName,
    packageRootOverrides,
    hasOverrideCatalog(packageRootOverride?: string) {
      return Boolean(
        packageRootOverride &&
          existsSync(resolve(packageRootOverride, RULE_CATALOG_FILENAME)),
      );
    },
  };
}

export function createCliInputDiagnostic(message: string): Diagnostic {
  return createDiagnostic({
    code: 'cli.input.invalid',
    message,
  });
}
