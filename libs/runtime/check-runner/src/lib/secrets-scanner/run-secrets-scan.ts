import {
  aggregateDiagnostics,
  createDiagnostic,
  type Diagnostic,
} from '@critiq/core-diagnostics';
import type { DiffRange } from '@critiq/core-rules-engine';
import {
  loadCritiqConfigForDirectory,
  normalizeSecretsScanConfig,
  type NormalizedCritiqConfig,
} from '@critiq/core-config';
import { statSync } from 'node:fs';

import {
  collectRawSecretMatches,
  rawMatchesToFindings,
} from './detectors';
import {
  isSecretsEligiblePath,
  SECRETS_SCAN_MAX_FILE_BYTES,
} from './eligibility';
import type { RunSecretsScanOptions, RunSecretsScanResult } from './types';
import {
  determineExitCode,
  readTextFileSafe,
  toDisplayPath,
  type CheckResolvedScope,
  type CheckSecretsScanPayload,
} from '../check-runner/shared';
import {
  filterIgnoredPaths,
  readGitStagedFileText,
  resolveCheckTarget,
  resolveSecretsScanScope,
} from '../check-runner/scope';

function mergeSecretsIgnorePaths(
  config: NormalizedCritiqConfig,
  optionPaths: readonly string[] | undefined,
): string[] {
  return Array.from(
    new Set([
      ...config.ignorePaths,
      ...config.secretsScan.ignorePaths,
      ...(optionPaths ?? []),
    ]),
  ).sort((left, right) => left.localeCompare(right));
}

function lineOverlapsDiffRanges(
  startLine: number,
  endLine: number,
  ranges: readonly DiffRange[],
): boolean {
  if (ranges.length === 0) {
    return true;
  }

  return ranges.some(
    (range) => !(endLine < range.startLine || startLine > range.endLine),
  );
}

function buildSecretScanScope(
  scopeData: CheckResolvedScope,
): RunSecretsScanResult['scope'] {
  if (scopeData.scope.mode === 'diff') {
    return {
      mode: 'diff',
      base: scopeData.scope.base,
      head: scopeData.scope.head,
      changedFileCount: scopeData.scope.changedFileCount,
    };
  }

  if (scopeData.scope.mode === 'staged') {
    return {
      mode: 'staged',
      changedFileCount: scopeData.scope.changedFileCount ?? 0,
    };
  }

  return { mode: 'repo' };
}

export function runSecretsScan(
  options: RunSecretsScanOptions = {},
): RunSecretsScanResult {
  const cwd = options.cwd ?? process.cwd();
  const target = options.target ?? '.';
  const resolvedTarget = resolveCheckTarget(cwd, target);

  if (!resolvedTarget.success) {
    const { diagnostics } = resolvedTarget as Extract<
      typeof resolvedTarget,
      { success: false }
    >;
    const aggregated = aggregateDiagnostics(diagnostics);

    return {
      scope: { mode: 'repo' },
      scannedFileCount: 0,
      findingCount: 0,
      findings: [],
      diagnostics: aggregated,
      exitCode: determineExitCode(aggregated) || 1,
    };
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
  const diagnostics: Diagnostic[] = [];

  if (loadedConfig.success) {
    effectiveConfig = loadedConfig.data;
  } else {
    const loadDiagnostics = (
      loadedConfig as Extract<typeof loadedConfig, { success: false }>
    ).diagnostics;

    if (
      loadDiagnostics.length !== 1 ||
      loadDiagnostics[0]?.code !== 'config.file.not-found'
    ) {
      const aggregated = aggregateDiagnostics(loadDiagnostics);

      return {
        scope: { mode: 'repo' },
        scannedFileCount: 0,
        findingCount: 0,
        findings: [],
        diagnostics: aggregated,
        exitCode: determineExitCode(aggregated) || 1,
      };
    }
  }

  const includeTests =
    options.includeTests ?? effectiveConfig.includeTests;
  const ignorePaths = mergeSecretsIgnorePaths(effectiveConfig, options.ignorePaths);
  const disabledDetectors = new Set(
    effectiveConfig.secretsScan.disabledDetectors,
  );
  const suppressedFingerprints = new Set(
    effectiveConfig.secretsScan.suppressFingerprints,
  );

  const resolvedScope = resolveSecretsScanScope(
    resolvedTarget.data,
    options.baseRef,
    options.headRef,
    options.staged ?? false,
  );

  if (!resolvedScope.success) {
    const { diagnostics: scopeDiagnostics } = resolvedScope as Extract<
      typeof resolvedScope,
      { success: false }
    >;
    const aggregated = aggregateDiagnostics(scopeDiagnostics);

    return {
      scope: { mode: 'repo' },
      scannedFileCount: 0,
      findingCount: 0,
      findings: [],
      diagnostics: aggregated,
      exitCode: determineExitCode(aggregated) || 1,
    };
  }

  const filtered = filterIgnoredPaths(
    resolvedScope.data.files,
    resolvedScope.data.changedRangesByAbsolutePath,
    resolvedTarget.data.displayRoot,
    includeTests,
    ignorePaths,
  );

  const scope = buildSecretScanScope(resolvedScope.data);
  const isStagedScope = resolvedScope.data.scope.mode === 'staged';
  const isDiffMode =
    resolvedScope.data.scope.mode === 'diff' || isStagedScope;
  const repoRoot = resolvedTarget.data.repoRoot;
  const findings: RunSecretsScanResult['findings'] = [];
  const seenFingerprints = new Set<string>();
  let scannedFileCount = 0;

  for (const absolutePath of filtered.files) {
    const displayPath = toDisplayPath(
      resolvedTarget.data.displayRoot,
      absolutePath,
    );

    if (!isSecretsEligiblePath(displayPath)) {
      continue;
    }

    let text: string;

    if (isStagedScope) {
      if (!repoRoot) {
        continue;
      }

      const stagedRead = readGitStagedFileText(repoRoot, absolutePath);

      if (!stagedRead.success) {
        const { diagnostics: readDiag } = stagedRead as Extract<
          typeof stagedRead,
          { success: false }
        >;
        diagnostics.push(...readDiag);
        continue;
      }

      text = stagedRead.text;
    } else {
      let size = 0;

      try {
        size = statSync(absolutePath).size;
      } catch {
        continue;
      }

      if (size > SECRETS_SCAN_MAX_FILE_BYTES) {
        diagnostics.push(
          createDiagnostic({
            code: 'secrets.scan.file.skipped',
            severity: 'info',
            message: `Skipped secrets scan for \`${displayPath}\` (file larger than ${String(SECRETS_SCAN_MAX_FILE_BYTES)} bytes).`,
            details: {
              path: displayPath,
              size,
              maxBytes: SECRETS_SCAN_MAX_FILE_BYTES,
            },
          }),
        );
        continue;
      }

      const textResult = readTextFileSafe(absolutePath);

      if (!textResult.success) {
        const { diagnostics: readDiag } = textResult as Extract<
          typeof textResult,
          { success: false }
        >;
        diagnostics.push(...readDiag);
        continue;
      }

      text = textResult.text;
    }

    scannedFileCount += 1;
    const raw = collectRawSecretMatches(text, { disabledDetectors });
    const changedRanges =
      filtered.changedRangesByAbsolutePath.get(absolutePath) ?? [];

    for (const finding of rawMatchesToFindings(displayPath, text, raw)) {
      const { startLine, endLine } = finding.locations.primary;

      if (
        isDiffMode &&
        !lineOverlapsDiffRanges(startLine, endLine, changedRanges)
      ) {
        continue;
      }

      if (suppressedFingerprints.has(finding.fingerprint)) {
        continue;
      }

      if (seenFingerprints.has(finding.fingerprint)) {
        continue;
      }

      seenFingerprints.add(finding.fingerprint);
      findings.push(finding);
    }
  }

  const aggregatedDiagnostics = aggregateDiagnostics(diagnostics);
  const diagnosticExit = determineExitCode(aggregatedDiagnostics);
  const failOnFindings = options.failOnFindings ?? true;
  const exitCode =
    diagnosticExit !== 0
      ? diagnosticExit
      : findings.length > 0 && failOnFindings
        ? 1
        : 0;

  return {
    scope,
    scannedFileCount,
    findingCount: findings.length,
    findings,
    diagnostics: aggregatedDiagnostics,
    exitCode,
  };
}

export function toCheckSecretsScanPayload(
  result: RunSecretsScanResult,
): CheckSecretsScanPayload {
  const scope: CheckSecretsScanPayload['scope'] =
    result.scope.mode === 'diff'
      ? {
          mode: 'diff',
          base: result.scope.base ?? '',
          head: result.scope.head ?? '',
          changedFileCount: result.scope.changedFileCount ?? 0,
        }
      : result.scope.mode === 'staged'
        ? {
            mode: 'staged',
            changedFileCount: result.scope.changedFileCount ?? 0,
          }
        : { mode: 'repo' };

  return {
    scope,
    scannedFileCount: result.scannedFileCount,
    findingCount: result.findingCount,
    findings: result.findings,
    diagnostics: result.diagnostics,
  };
}
