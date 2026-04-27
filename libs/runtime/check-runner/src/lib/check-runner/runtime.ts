import {
  detectRepositoryLanguages,
  filterNormalizedRulesForCatalog,
  loadRuleCatalogFile,
  resolveCatalogPackage,
  resolveCatalogRulePaths,
} from '@critiq/core-catalog';
import {
  loadCritiqConfigForDirectory,
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
import { resolve } from 'node:path';

import { applySeverityOverride, compareFindings, summarizeFindings } from './findings';
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

  return {
    envelope: {
      command: 'check',
      format: options.format,
      target: options.target,
      catalogPackage: options.catalogPackage,
      preset: options.preset,
      scope: buildScopeFallback(baseRef, headRef),
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
export type {
  CheckProgressUpdate,
  CheckCommandEnvelope,
  CheckOverallRuleResult,
  CheckRuleSummary,
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

  const filteredScope = filterIgnoredPaths(
    resolvedScope.data.files,
    resolvedScope.data.changedRangesByAbsolutePath,
    resolvedTarget.data.displayRoot,
    effectiveConfig.includeTests,
    effectiveConfig.ignorePaths,
  );
  options.onProgress?.({
    step: 'preparing',
    scannedFileCount: 0,
    totalFileCount: filteredScope.files.length,
  });
  const detectedLanguages = detectRepositoryLanguages(filteredScope.files);
  const activeRules = filterNormalizedRulesForCatalog(
    loadedRules.rules,
    {
      ...effectiveConfig,
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
  const analyzedFiles: AnalyzedFile[] = [];
  let processedFileCount = 0;

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
    scopeMode: resolvedScope.data.scope.mode,
  });

  for (const analyzedFile of projectAugmentedFiles) {
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
      preset: effectiveConfig.preset,
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
