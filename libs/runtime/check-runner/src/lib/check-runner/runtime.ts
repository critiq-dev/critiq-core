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
  evaluateRuleApplicability,
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
import { filterIgnoredPaths, resolveCheckScope, resolveCheckTarget } from './scope';
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
  createCliInputDiagnostic,
  determineExitCode,
  hasGlobMagic,
  toDisplayPath,
  toPosixPath,
  walkFiles,
} from './shared';
export type {
  CheckCommandEnvelope,
  CheckCommandProvenance,
  CheckOverallRuleResult,
  CheckProgressUpdate,
  CheckReportFinding,
  CheckReportFindingAttributes,
  CheckRuleSummary,
  CheckSecretsScanFinding,
  CheckSecretsScanFindingLocation,
  CheckSecretsScanPayload,
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

  const loadedConfig = loadCritiqConfigForDirectory(
    resolvedTarget.data.displayRoot,
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

  let effectiveConfig: NormalizedCritiqConfig = defaultConfig;

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

  const catalogPackageName =
    effectiveConfig.catalogPackage ??
    options.defaultCatalogPackage ??
    DEFAULT_CATALOG_PACKAGE_NAME;
  const resolvedCatalogPackage = resolveCatalogPackageRuntime(
    resolvedTarget.data.displayRoot,
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

  const resolvedScope = resolveCheckScope(
    resolvedTarget.data,
    options.baseRef,
    options.headRef,
    registry,
  );

  if (!resolvedScope.success) {
    const { diagnostics } = resolvedScope as Extract<
      typeof resolvedScope,
      { success: false }
    >;
    return buildFailureResult(
      {
        format,
        target,
        catalogPackage: catalogPackageName,
        preset: effectiveConfig.preset,
        matchedRuleCount: loadedRules.rules.length,
        diagnostics,
      },
      options.baseRef,
      options.headRef,
    );
  }

  const catalogScope = filterIgnoredPaths(
    resolvedScope.data.files,
    resolvedScope.data.changedRangesByAbsolutePath,
    resolvedTarget.data.displayRoot,
    effectiveConfig.includeTests,
    effectiveConfig.ignorePaths,
  );
  const analysisScope = filterIgnoredPaths(
    resolvedScope.data.files,
    resolvedScope.data.changedRangesByAbsolutePath,
    resolvedTarget.data.displayRoot,
    true,
    effectiveConfig.ignorePaths,
  );
  options.onProgress?.({
    step: 'preparing',
    scannedFileCount: 0,
    totalFileCount: catalogScope.files.filter((path) =>
      Boolean(registry.findAdapterForPath(path)),
    ).length,
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
  const filteredScope = {
    files: catalogScope.files.filter((path) => Boolean(registry.findAdapterForPath(path))),
    changedRangesByAbsolutePath: catalogScope.changedRangesByAbsolutePath,
  };
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

  for (const absolutePath of analysisScope.files) {
    const displayPath = toDisplayPath(
      resolvedTarget.data.displayRoot,
      absolutePath,
    );

    if (!isDependencyManifestPath(displayPath)) {
      continue;
    }

    const textResult = readTextFileSafe(absolutePath);

    if (textResult.success) {
      dependencyManifestInputs.push({
        path: displayPath,
        text: textResult.text,
      });
    }
  }

  for (const absolutePath of filteredScope.files) {
    const displayPath = toDisplayPath(
      resolvedTarget.data.displayRoot,
      absolutePath,
    );
    options.onProgress?.({
      step: 'scanning',
      scannedFileCount: processedFileCount,
      totalFileCount: filteredScope.files.length,
      currentFilePath: displayPath,
    });
    const textResult = readTextFileSafe(absolutePath);

    if (!textResult.success) {
      const { diagnostics: textDiagnostics } = textResult as Extract<
        typeof textResult,
        { success: false }
      >;
      diagnostics.push(...textDiagnostics);
      processedFileCount += 1;
      options.onProgress?.({
        step: 'scanning',
        scannedFileCount: processedFileCount,
        totalFileCount: filteredScope.files.length,
        currentFilePath: displayPath,
      });
      continue;
    }

    sourceTextsByPath.set(displayPath, textResult.text);

    const adapter = registry.findAdapterForPath(displayPath);

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
        totalFileCount: filteredScope.files.length,
        currentFilePath: displayPath,
      });
      continue;
    }

    const analysis = adapter.analyze(displayPath, textResult.text);

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
        totalFileCount: filteredScope.files.length,
        currentFilePath: displayPath,
      });
      continue;
    }

    analyzedFiles.push({
      ...analysis.data,
      changedRanges: filteredScope.changedRangesByAbsolutePath.get(absolutePath),
    });
    processedFileCount += 1;
    options.onProgress?.({
      step: 'scanning',
      scannedFileCount: processedFileCount,
      totalFileCount: filteredScope.files.length,
      currentFilePath: displayPath,
    });
  }

  options.onProgress?.({
    step: 'finalizing',
    scannedFileCount: processedFileCount,
    totalFileCount: filteredScope.files.length,
  });

  const projectAugmentedFiles = augmentProjectFacts(analyzedFiles, {
    scopeMode:
      resolvedScope.data.scope.mode === 'diff' ||
      resolvedScope.data.scope.mode === 'staged'
        ? 'diff'
        : 'repo',
    availableTestPaths: new Set(
      analysisScope.files
        .map((absolutePath) =>
          toDisplayPath(resolvedTarget.data.displayRoot, absolutePath),
        )
        .filter((path) => isTestPath(path)),
    ),
    availableChangedTestPaths: new Set(
      analysisScope.files
        .map((absolutePath) => ({
          path: toDisplayPath(resolvedTarget.data.displayRoot, absolutePath),
          changedRanges:
            analysisScope.changedRangesByAbsolutePath.get(absolutePath) ?? [],
        }))
        .filter(
          (file) => isTestPath(file.path) && file.changedRanges.length > 0,
        )
        .map((file) => file.path),
    ),
    dependencyFacts: collectProjectDependencyFacts(dependencyManifestInputs),
  });

  for (const analyzedFile of projectAugmentedFiles) {
    for (const rule of activeRules) {
      const applicability = evaluateRuleApplicability(rule, analyzedFile);

      if (!applicability.applicable) {
        continue;
      }

      for (const match of evaluateRule(rule, analyzedFile)) {
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
    }
  }

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
      preset: effectiveConfig.preset,
      scope:
        resolvedScope.data.scope.mode === 'diff'
          ? {
              ...resolvedScope.data.scope,
              changedFileCount: filteredScope.files.length,
            }
          : resolvedScope.data.scope,
      provenance: {
        engineKind: CHECK_ENGINE_KIND,
        engineVersion: CHECK_ENGINE_VERSION,
        rulePack: catalogPackageName,
        generatedAt,
      },
      scannedFileCount: filteredScope.files.length,
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
