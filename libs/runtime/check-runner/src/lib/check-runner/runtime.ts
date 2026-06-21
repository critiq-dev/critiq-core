import {
  detectRepositoryLanguages,
  filterNormalizedRulesForCatalog,
  loadRuleCatalogFile,
  resolveCatalogPackage,
  resolveCatalogRulePaths,
} from '@critiq/core-catalog';
import {
  loadCritiqConfigForDirectory,
  normalizeSecretsScanConfig,
  type NormalizedCritiqConfig,
} from '@critiq/core-config';
import {
  aggregateDiagnostics,
  createDiagnostic,
  type Diagnostic,
} from '@critiq/core-diagnostics';
import type { FindingV0 } from '@critiq/core-finding-schema';
import {
  buildFinding,
  evaluateRule,
  type AnalyzedFile,
} from '@critiq/core-rules-engine';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  applySeverityOverride,
  compareFindings,
  compactFindingForReport,
  dedupeReportFindings,
  summarizeFindings,
} from './findings';
import { createDefaultSourceAdapterRegistry } from './registry';
import { RuleIndex } from './rule-index';
import { filterIgnoredPaths, resolveCheckScope, resolveCheckTarget } from './scope';
import type { ScanContext, ScanFileTextCacheFailure } from './scan-context';
import {
  DEFAULT_CATALOG_PACKAGE_NAME,
  RULE_CATALOG_FILENAME,
  createCheckRuntimeDiagnostic,
  determineExitCode,
  loadNormalizedRulesForCatalog,
  readTextFileSafe,
  resolveCatalogPackageForRuntime,
  toDisplayPath,
  type CheckCommandEnvelope,
  type CheckOverallRuleResult,
  type RunCheckCommandOptions,
  type RunCheckCommandResult,
} from './shared';
import { augmentProjectFacts } from '../project-analysis';
import {
  collectProjectDependencyFacts,
  isDependencyManifestPath,
  type DependencyManifestInput,
} from '../project-analysis';
import { isTestPath } from '../project-analysis/context';

const CHECK_ENGINE_KIND = 'critiq-cli' as const;

function loadCheckEngineVersion(): string {
  const candidatePaths = [
    resolve(__dirname, './package.json'),
    resolve(__dirname, '../package.json'),
    resolve(__dirname, '../../../package.json'),
  ];

  try {
    for (const candidatePath of candidatePaths) {
      try {
        const packageJson = JSON.parse(
          readFileSync(candidatePath, 'utf8'),
        ) as { version?: string };

        if (packageJson.version && packageJson.version.trim().length > 0) {
          return packageJson.version.trim();
        }
      } catch {
        // Try the next package.json candidate.
      }
    }
  } catch {
    // Fall back to the previous workspace default when package metadata is unavailable.
  }

  return '0.0.1';
}

const CHECK_ENGINE_VERSION = loadCheckEngineVersion();

function buildScopeFallback(
  baseRef?: string,
  headRef?: string,
): CheckCommandEnvelope['scope'] {
  return baseRef && headRef
    ? {
        mode: 'diff',
        base: baseRef,
        head: headRef,
        changedFileCount: 0,
      }
    : {
        mode: 'repo',
      };
}

function buildFailureResult(
  options: {
    format: 'pretty' | 'json';
    target: string;
    catalogPackage: string | null;
    preset: CheckCommandEnvelope['preset'];
    matchedRuleCount?: number;
    diagnostics: Diagnostic[];
  },
  baseRef?: string,
  headRef?: string,
): RunCheckCommandResult {
  const diagnostics = aggregateDiagnostics(options.diagnostics);
  const generatedAt = new Date().toISOString();

  return {
    envelope: {
      command: 'check',
      format: options.format,
      target: options.target,
      catalogPackage: options.catalogPackage,
      preset: options.preset,
      scope: buildScopeFallback(baseRef, headRef),
      provenance: {
        engineKind: CHECK_ENGINE_KIND,
        engineVersion: CHECK_ENGINE_VERSION,
        rulePack: options.catalogPackage ?? undefined,
        generatedAt,
      },
      scannedFileCount: 0,
      matchedRuleCount: options.matchedRuleCount ?? 0,
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

function resolveCatalogPackageRuntime(
  displayRoot: string,
  packageName: string,
  options: RunCheckCommandOptions,
) {
  const packageRuntime = resolveCatalogPackageForRuntime(
    displayRoot,
    packageName,
    options,
  );
  const packageRootOverride =
    packageRuntime.packageRootOverrides[packageRuntime.packageName];

  if (packageRuntime.hasOverrideCatalog(packageRootOverride)) {
    return {
      success: true as const,
      data: {
        packageName,
        packageRoot: packageRootOverride,
        entryPath: resolve(packageRootOverride as string, 'package.json'),
        catalogPath: resolve(
          packageRootOverride as string,
          RULE_CATALOG_FILENAME,
        ),
      },
    };
  }

  return resolveCatalogPackage(displayRoot, packageName, [
    ...(options.catalogResolverBasePaths ?? []),
  ]);
}

export { createDefaultSourceAdapterRegistry } from './registry';
export { createSourceAdapterRegistry } from './registry';
export { filterIgnoredPaths, resolveCheckScope, resolveCheckTarget, resolveSecretsScanScope } from './scope';
export {
  BenchmarkCollector,
  createCliInputDiagnostic,
  DEFAULT_CATALOG_PACKAGE_NAME,
  determineExitCode,
  hasGlobMagic,
  toDisplayPath,
  toPosixPath,
  walkFiles,
} from './shared';
export type {
  AdapterBenchmark,
  BenchmarkReport,
  BenchmarkSummary,
  CheckCommandEnvelope,
  CheckCommandProvenance,
  CheckOverallRuleResult,
  CheckProgressUpdate,
  CheckReportFinding,
  CheckReportFindingAttributes,
  CheckRuleSummary,
  CheckScanProfile,
  CheckScanProfileTimings,
  CheckSecretsScanFinding,
  CheckSecretsScanFindingLocation,
  CheckSecretsScanPayload,
  FileBenchmarkEntry,
  LanguageBenchmark,
  PreloadBenchmark,
  RuleBenchmark,
  RuleBenchmarkEntry,
  RunCheckCommandOptions,
  RunCheckCommandResult,
  SourceAdapter,
  SourceAdapterAnalysisFailure,
  SourceAdapterAnalysisResult,
  SourceAdapterAnalysisSuccess,
  SourceAdapterRegistry,
} from './shared';

export function runCheckCommand(
  options: RunCheckCommandOptions = {},
): RunCheckCommandResult {
  const cwd = options.cwd ?? process.cwd();
  const format = options.format ?? 'pretty';
  const target = options.target ?? '.';
  const registry =
    options.adapterRegistry ?? createDefaultSourceAdapterRegistry();
  const profile = options.profile;
  const benchmark = options.benchmark;
  const scanContext = options.scanContext;

  profile?.mark('config:start');

  let resolvedTargetData: ScanContext['resolvedTarget'];
  let effectiveConfig: NormalizedCritiqConfig;
  let repoScope: ScanContext['repoScope'];
  let catalogScope: ScanContext['catalogFilteredScope'];
  let analysisScope: ScanContext['analysisFilteredScope'];
  let readFileText: ScanContext['readCachedText'];

  if (scanContext) {
    resolvedTargetData = scanContext.resolvedTarget;
    effectiveConfig = scanContext.effectiveConfig;
    repoScope = scanContext.repoScope;
    catalogScope = scanContext.catalogFilteredScope;
    analysisScope = scanContext.analysisFilteredScope;
    readFileText = scanContext.readCachedText.bind(scanContext);
    profile?.mark('scope:end');
    profile?.mark('config:end');
    profile?.mark('filter:end');
  } else {
    profile?.mark('scope:start');
    const resolvedTarget = resolveCheckTarget(cwd, target);

    if (!resolvedTarget.success) {
      const { diagnostics } = resolvedTarget as Extract<
        typeof resolvedTarget,
        { success: false }
      >;
      return buildFailureResult(
        {
          format,
          target,
          catalogPackage: null,
          preset: null,
          diagnostics,
        },
        options.baseRef,
        options.headRef,
      );
    }

    resolvedTargetData = resolvedTarget.data;

    const loadedConfig = loadCritiqConfigForDirectory(
      resolvedTargetData.displayRoot,
    );
    const defaultConfig: NormalizedCritiqConfig = {
      apiVersion: 'critiq.dev/v1alpha1' as const,
      kind: 'CritiqConfig' as const,
      catalogPackage: undefined,
      preset: 'recommended' as const,
      disableRules: [],
      disableCategories: [],
      disableLanguages: [],
      includeTests: false,
      ignorePaths: [],
      severityOverrides: {},
      secretsScan: normalizeSecretsScanConfig(undefined),
    };

    effectiveConfig = defaultConfig;

    if (loadedConfig.success) {
      effectiveConfig = loadedConfig.data;
    } else {
      const diagnostics = (
        loadedConfig as Extract<typeof loadedConfig, { success: false }>
      ).diagnostics;

      if (
        diagnostics.length !== 1 ||
        diagnostics[0]?.code !== 'config.file.not-found'
      ) {
        return buildFailureResult(
          {
            format,
            target,
            catalogPackage: null,
            preset: null,
            diagnostics,
          },
          options.baseRef,
          options.headRef,
        );
      }
    }

    profile?.mark('config:end');

    const resolvedScope = resolveCheckScope(
      resolvedTargetData,
      options.baseRef,
      options.headRef,
      registry,
    );

    profile?.mark('scope:end');

    if (!resolvedScope.success) {
      const { diagnostics } = resolvedScope as Extract<
        typeof resolvedScope,
        { success: false }
      >;
      return buildFailureResult(
        {
          format,
          target,
          catalogPackage:
            effectiveConfig.catalogPackage ??
            options.defaultCatalogPackage ??
            DEFAULT_CATALOG_PACKAGE_NAME,
          preset: effectiveConfig.preset,
          diagnostics,
        },
        options.baseRef,
        options.headRef,
      );
    }

    repoScope = resolvedScope.data;
    profile?.mark('filter:start');
    catalogScope = filterIgnoredPaths(
      repoScope.files,
      repoScope.changedRangesByAbsolutePath,
      resolvedTargetData.displayRoot,
      effectiveConfig.includeTests,
      effectiveConfig.ignorePaths,
    );
    analysisScope = filterIgnoredPaths(
      repoScope.files,
      repoScope.changedRangesByAbsolutePath,
      resolvedTargetData.displayRoot,
      true,
      effectiveConfig.ignorePaths,
    );
    profile?.mark('filter:end');
    readFileText = (absolutePath: string) => readTextFileSafe(absolutePath);
  }

  profile?.mark('catalog:start');
  const catalogPackageName =
    effectiveConfig.catalogPackage ??
    options.defaultCatalogPackage ??
    DEFAULT_CATALOG_PACKAGE_NAME;
  const resolvedCatalogPackage = resolveCatalogPackageRuntime(
    resolvedTargetData.displayRoot,
    catalogPackageName,
    options,
  );

  if (!resolvedCatalogPackage.success) {
    const { diagnostics } = resolvedCatalogPackage as Extract<
      typeof resolvedCatalogPackage,
      { success: false }
    >;
    return buildFailureResult(
      {
        format,
        target,
        catalogPackage: catalogPackageName,
        preset: effectiveConfig.preset,
        diagnostics,
      },
      options.baseRef,
      options.headRef,
    );
  }

  const loadedCatalog = loadRuleCatalogFile(
    resolvedCatalogPackage.data.catalogPath,
  );

  if (!loadedCatalog.success) {
    const { diagnostics } = loadedCatalog as Extract<
      typeof loadedCatalog,
      { success: false }
    >;
    return buildFailureResult(
      {
        format,
        target,
        catalogPackage: catalogPackageName,
        preset: effectiveConfig.preset,
        diagnostics,
      },
      options.baseRef,
      options.headRef,
    );
  }

  const catalogRuleEntries = resolveCatalogRulePaths(
    loadedCatalog.data,
    resolvedCatalogPackage.data.packageRoot,
    effectiveConfig.preset,
  );
  const loadedRules = loadNormalizedRulesForCatalog(
    catalogRuleEntries.map((entry) => entry.rulePath),
  );

  if (!loadedRules.success) {
    return buildFailureResult(
      {
        format,
        target,
        catalogPackage: catalogPackageName,
        preset: effectiveConfig.preset,
        matchedRuleCount: loadedRules.rules.length,
        diagnostics: loadedRules.diagnostics,
      },
      options.baseRef,
      options.headRef,
    );
  }

  profile?.mark('catalog:end');

  options.onProgress?.({
    step: 'preparing',
    scannedFileCount: 0,
    totalFileCount: catalogScope.files.length,
  });
  const detectedLanguages = detectRepositoryLanguages(catalogScope.files);
  const scannableLanguages = detectedLanguages.filter((language) =>
    registry.hasAdapterForLanguage(language),
  );
  const activeRules = filterNormalizedRulesForCatalog(
    loadedRules.rules,
    {
      ...effectiveConfig,
      catalogPackage: catalogPackageName,
    },
    scannableLanguages,
  );
  const ruleIndex = new RuleIndex(activeRules);
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
  } else if (scannableLanguages.length < detectedLanguages.length) {
    const unsupportedLanguages = detectedLanguages.filter(
      (language) => !registry.hasAdapterForLanguage(language),
    );

    informationalDiagnostics.push(
      createDiagnostic({
        code: 'catalog.repo.no-adapter-for-language',
        severity: 'info',
        message: `Repository languages were detected without registered adapters: ${unsupportedLanguages.join(
          ', ',
        )}.`,
        details: {
          languages: unsupportedLanguages,
        },
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
  const analyzedFiles: AnalyzedFile[] = [];
  const dependencyManifestInputs: DependencyManifestInput[] = [];
  let processedFileCount = 0;
  const generatedAt = new Date().toISOString();

  profile?.mark('analyze:start');

  for (const absolutePath of analysisScope.files) {
    const displayPath = toDisplayPath(
      resolvedTargetData.displayRoot,
      absolutePath,
    );

    if (!isDependencyManifestPath(displayPath)) {
      continue;
    }

    const textResult = readFileText(absolutePath);

    if (textResult.success) {
      dependencyManifestInputs.push({
        path: displayPath,
        text: textResult.text,
      });
    }
  }

  for (const absolutePath of catalogScope.files) {
    const displayPath = toDisplayPath(
      resolvedTargetData.displayRoot,
      absolutePath,
    );
    options.onProgress?.({
      step: 'scanning',
      scannedFileCount: processedFileCount,
      totalFileCount: catalogScope.files.length,
      currentFilePath: displayPath,
    });
    const textResult = readFileText(absolutePath);

    if (!textResult.success) {
      diagnostics.push(
        ...(textResult as ScanFileTextCacheFailure).diagnostics,
      );
      processedFileCount += 1;
      options.onProgress?.({
        step: 'scanning',
        scannedFileCount: processedFileCount,
        totalFileCount: catalogScope.files.length,
        currentFilePath: displayPath,
      });
      continue;
    }

    sourceTextsByPath.set(displayPath, textResult.text);

    const adapter = registry.findAdapterForPath(displayPath, textResult.text);

    if (!adapter) {
      diagnostics.push(
        createCheckRuntimeDiagnostic(
          'catalog.repo.no-adapter',
          `No source adapter is registered for \`${displayPath}\`.`,
        ),
      );
      processedFileCount += 1;
      options.onProgress?.({
        step: 'scanning',
        scannedFileCount: processedFileCount,
        totalFileCount: catalogScope.files.length,
        currentFilePath: displayPath,
      });
      continue;
    }

    const effectiveMaxFileSizeKb = options.maxFileSizeKb ?? 512;
    const fileSizeKb = Buffer.byteLength(textResult.text, 'utf8') / 1024;

    if (fileSizeKb > effectiveMaxFileSizeKb) {
      diagnostics.push(
        createCheckRuntimeDiagnostic(
          'runtime.file.too-large',
          `Skipped \`${displayPath}\` (${Math.round(fileSizeKb)} KB, limit is ${effectiveMaxFileSizeKb} KB).`,
          {
            path: displayPath,
            sizeKb: Math.round(fileSizeKb),
            maxFileSizeKb: effectiveMaxFileSizeKb,
          },
        ),
      );
      processedFileCount += 1;
      options.onProgress?.({
        step: 'scanning',
        scannedFileCount: processedFileCount,
        totalFileCount: catalogScope.files.length,
        currentFilePath: displayPath,
      });
      continue;
    }

    const analyzeStart = performance.now();
    const analysis = adapter.analyze(displayPath, textResult.text);
    const analyzeMs = performance.now() - analyzeStart;

    if (!analysis.success) {
      const { diagnostics: analysisDiagnostics } = analysis as Extract<
        typeof analysis,
        { success: false }
      >;
      diagnostics.push(...analysisDiagnostics);
      processedFileCount += 1;
      options.onProgress?.({
        step: 'scanning',
        scannedFileCount: processedFileCount,
        totalFileCount: catalogScope.files.length,
        currentFilePath: displayPath,
      });
      continue;
    }

    benchmark?.recordAdapterAnalyze(
      adapter.packageName,
      analysis.data.language,
      displayPath,
      analyzeMs,
    );

    if (analysis.diagnostics?.length) {
      diagnostics.push(...analysis.diagnostics);
    }

    analyzedFiles.push({
      ...analysis.data,
      changedRanges: catalogScope.changedRangesByAbsolutePath.get(absolutePath),
    });
    processedFileCount += 1;
    options.onProgress?.({
      step: 'scanning',
      scannedFileCount: processedFileCount,
      totalFileCount: catalogScope.files.length,
      currentFilePath: displayPath,
    });
  }

  options.onProgress?.({
    step: 'finalizing',
    scannedFileCount: processedFileCount,
    totalFileCount: catalogScope.files.length,
  });

  profile?.mark('analyze:end');
  profile?.mark('project:start');

  const isDiffMode =
    repoScope.scope.mode === 'diff' || repoScope.scope.mode === 'staged';
  const testPaths: string[] = [];
  const changedTestPaths: string[] = [];

  for (const absolutePath of analysisScope.files) {
    const displayPath = toDisplayPath(
      resolvedTargetData.displayRoot,
      absolutePath,
    );

    if (!isTestPath(displayPath)) {
      continue;
    }

    testPaths.push(displayPath);

    if (isDiffMode) {
      const changedRanges =
        analysisScope.changedRangesByAbsolutePath.get(absolutePath);

      if (changedRanges && changedRanges.length > 0) {
        changedTestPaths.push(displayPath);
      }
    }
  }

  const projectAugmentedFiles = augmentProjectFacts(analyzedFiles, {
    scopeMode: isDiffMode ? 'diff' : 'repo',
    availableTestPaths: new Set(testPaths),
    ...(changedTestPaths.length > 0 && {
      availableChangedTestPaths: new Set(changedTestPaths),
    }),
    dependencyFacts: collectProjectDependencyFacts(dependencyManifestInputs),
  });

  profile?.mark('project:end');
  profile?.mark('ruleEval:start');

  for (const analyzedFile of projectAugmentedFiles) {
    const candidateRules = ruleIndex.getCandidateRules(analyzedFile);

    for (const rule of candidateRules) {
      const evalStart = performance.now();
      let matchCount = 0;

      for (const match of evaluateRule(rule, analyzedFile, {
        skipApplicabilityCheck: true,
      })) {
        matchCount += 1;

        const buildResult = buildFinding(rule, analyzedFile, match, {
          engineKind: CHECK_ENGINE_KIND,
          engineVersion: CHECK_ENGINE_VERSION,
          generatedAt,
          rulePack: catalogPackageName,
        });

        if (!buildResult.success) {
          const { issues } = buildResult as Extract<
            typeof buildResult,
            { success: false }
          >;
          diagnostics.push(
            ...issues.map((issue) =>
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
            effectiveConfig.severityOverrides[buildResult.finding.rule.id],
          ),
        );
      }

      benchmark?.recordRuleEval(
        rule.ruleId,
        performance.now() - evalStart,
        matchCount > 0,
      );
    }
  }

  profile?.mark('ruleEval:end');

  const aggregatedDiagnostics = aggregateDiagnostics(diagnostics);
  const sortedFindings = [...findings].sort(compareFindings);
  const reportFindings = dedupeReportFindings(
    sortedFindings.map((finding) => compactFindingForReport(finding)),
  );
  const ruleSummaries = summarizeFindings(reportFindings);
  const exitCode =
    aggregatedDiagnostics.length > 0
      ? determineExitCode(aggregatedDiagnostics)
      : reportFindings.length > 0
        ? 1
        : 0;
  const failingRuleIds = new Set(
    sortedFindings.map((finding) => finding.rule.id),
  );
  const overallRuleResults: CheckOverallRuleResult[] = activeRules.map(
    (rule) => ({
      ruleId: rule.ruleId,
      status: failingRuleIds.has(rule.ruleId)
        ? ('failed' as const)
        : ('passed' as const),
    }),
  );

  return {
    envelope: {
      command: 'check',
      format,
      exitCode,
      target,
      catalogPackage: catalogPackageName,
      preset: effectiveConfig.preset,
      scope:
        repoScope.scope.mode === 'diff'
          ? {
              ...repoScope.scope,
              changedFileCount: catalogScope.files.length,
            }
          : repoScope.scope,
      provenance: {
        engineKind: CHECK_ENGINE_KIND,
        engineVersion: CHECK_ENGINE_VERSION,
        rulePack: catalogPackageName,
        generatedAt,
      },
      scannedFileCount: catalogScope.files.length,
      matchedRuleCount: activeRules.length,
      findingCount: reportFindings.length,
      findings: reportFindings,
      ruleSummaries,
      diagnostics: aggregatedDiagnostics,
    },
    overallRuleResults,
    sourceTextsByPath,
  };
}
