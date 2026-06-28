import { type Diagnostic } from '@critiq/core-diagnostics';

import {
  determineExitCode,
  type CheckCommandEnvelope,
  type RunCheckCommandResult,
} from './shared';
import { runCheckCommand, type RunCheckCommandOptions } from './runtime';
import { buildScanContext, collectPreloadPaths } from './scan-context';
import { ScanPhaseTimer, type CheckScanProfile } from './scan-profile';
import { BenchmarkCollector, type BenchmarkReport } from './benchmark-collector';
import { runSecretsScan, toCheckSecretsScanPayload } from '../secrets-scanner/run-secrets-scan';
import type { RunSecretsScanOptions } from '../secrets-scanner/types';

export interface RunCheckWithSecretsOptions
  extends Omit<RunCheckCommandOptions, 'profile' | 'scanContext' | 'benchmark'>,
    Pick<
      RunSecretsScanOptions,
      'staged' | 'includeTests' | 'ignorePaths' | 'failOnFindings'
    > {
  enableProfile?: boolean;
  enableSecrets?: boolean;
  enableBenchmark?: boolean;
}

export interface RunCheckWithSecretsResult {
  check: RunCheckCommandResult;
  profile?: CheckScanProfile;
  benchmark?: BenchmarkReport;
}

function buildContextFailureResult(
  options: RunCheckWithSecretsOptions,
  diagnostics: readonly Diagnostic[],
  profile?: CheckScanProfile,
): RunCheckCommandResult {
  const generatedAt = new Date().toISOString();

  const envelope: CheckCommandEnvelope = {
    command: 'check',
    format: options.format ?? 'pretty',
    exitCode: determineExitCode(diagnostics) || 1,
    target: options.target ?? '.',
    catalogPackage: null,
    preset: null,
    scope: { mode: 'repo' },
    provenance: {
      engineKind: 'critiq-cli',
      engineVersion: '0.0.1',
      generatedAt,
    },
    scannedFileCount: 0,
    matchedRuleCount: 0,
    findingCount: 0,
    findings: [],
    ruleSummaries: [],
    diagnostics: [...diagnostics],
    profile,
  };

  return {
    envelope,
    overallRuleResults: [],
    sourceTextsByPath: new Map(),
  };
}

function toCheckCommandOptions(
  options: RunCheckWithSecretsOptions,
): RunCheckCommandOptions {
  const {
    enableProfile: _enableProfile,
    enableSecrets: _enableSecrets,
    enableBenchmark: _enableBenchmark,
    staged: _staged,
    includeTests: _includeTests,
    ignorePaths: _ignorePaths,
    failOnFindings: _failOnFindings,
    ...checkOptions
  } = options;

  return checkOptions;
}

export async function runCheckWithSecretsScan(
  options: RunCheckWithSecretsOptions = {},
): Promise<RunCheckWithSecretsResult> {
  const timer = options.enableProfile || options.enableBenchmark ? new ScanPhaseTimer() : undefined;
  const benchmarkCollector = options.enableBenchmark
    ? new BenchmarkCollector()
    : undefined;
  timer?.mark('scope:start');
  timer?.mark('config:start');

  const contextResult = buildScanContext({
    cwd: options.cwd ?? process.cwd(),
    target: options.target,
    baseRef: options.baseRef,
    headRef: options.headRef,
    staged: options.staged,
    secretsIncludeTests: options.includeTests,
    secretsIgnorePaths: options.ignorePaths,
  });

  timer?.mark('scope:end');
  timer?.mark('config:end');
  timer?.mark('filter:start');
  timer?.mark('filter:end');

  if (!contextResult.success) {
    const finishedProfile = timer?.finish();
    const failureDiagnostics = (
      contextResult as Extract<typeof contextResult, { success: false }>
    ).diagnostics;

    return {
      check: buildContextFailureResult(
        options,
        failureDiagnostics,
        finishedProfile,
      ),
      profile: finishedProfile,
    };
  }

  const scanContext = contextResult.context;
  const checkOptions = toCheckCommandOptions(options);

  timer?.mark('preload:start');
  const preloadPaths = collectPreloadPaths(scanContext);
  await scanContext.preloadFiles(preloadPaths);
  timer?.mark('preload:end');
  benchmarkCollector?.recordPreload(
    preloadPaths.length,
    timer?.elapsedMs('preload:start', 'preload:end') ?? 0,
  );
  timer?.mark('secrets:start');

  const promiseCheck = Promise.resolve().then(() => {
    const r = runCheckCommand({
      ...checkOptions,
      scanContext,
      profile: timer,
      benchmark: benchmarkCollector,
    });
    return r;
  });

  if (options.enableSecrets) {
    const promiseSecrets = Promise.resolve().then(() => {
      const r = runSecretsScan({
        cwd: options.cwd,
        target: options.target,
        baseRef: options.baseRef,
        headRef: options.headRef,
        staged: options.staged,
        includeTests: options.includeTests,
        ignorePaths: options.ignorePaths,
        failOnFindings: options.failOnFindings,
        scanContext,
        profile: timer,
      });
      return r;
    });
    const [check, secretsResult] = await Promise.all([
      promiseCheck,
      promiseSecrets,
    ]);

    timer?.mark('secrets:end');

    const finishedProfile = timer?.finish();
    const benchmarkReport = benchmarkCollector?.finalize(
      {
        totalFiles: check.envelope.scannedFileCount,
        totalRules: check.envelope.matchedRuleCount,
        totalFindings: check.envelope.findingCount,
        scopeMode: check.envelope.scope.mode,
      },
      finishedProfile?.timings ?? {
        scopeResolveMs: 0,
        configLoadMs: 0,
        catalogLoadMs: 0,
        filterPathsMs: 0,
        filePreloadMs: 0,
        analyzeMs: 0,
        projectAnalysisMs: 0,
        ruleEvalMs: 0,
        secretsScanMs: 0,
        totalMs: 0,
      },
    );

    const secretsPayload = toCheckSecretsScanPayload(secretsResult);
    const envelope: CheckCommandEnvelope = {
      ...check.envelope,
      secretsScan: secretsPayload,
      profile: finishedProfile,
      benchmark: benchmarkReport,
    };

    return {
      check: {
        ...check,
        envelope,
      },
      profile: envelope.profile,
      benchmark: benchmarkReport,
    };
  }

  const check = await promiseCheck;

  timer?.mark('secrets:end');

  const finishedProfile = timer?.finish();
  const benchmarkReport = benchmarkCollector?.finalize(
    {
      totalFiles: check.envelope.scannedFileCount,
      totalRules: check.envelope.matchedRuleCount,
      totalFindings: check.envelope.findingCount,
      scopeMode: check.envelope.scope.mode,
    },
    finishedProfile?.timings ?? {
      scopeResolveMs: 0,
      configLoadMs: 0,
      catalogLoadMs: 0,
      filterPathsMs: 0,
      filePreloadMs: 0,
      analyzeMs: 0,
      projectAnalysisMs: 0,
      ruleEvalMs: 0,
      secretsScanMs: 0,
      totalMs: 0,
    },
  );

  const envelope: CheckCommandEnvelope = {
    ...check.envelope,
    secretsScan: {
      scope: check.envelope.scope,
      scannedFileCount: 0,
      findingCount: 0,
      findings: [],
      diagnostics: [],
    },
    profile: finishedProfile,
    benchmark: benchmarkReport,
  };

  return {
    check: {
      ...check,
      envelope,
    },
    profile: envelope.profile,
    benchmark: benchmarkReport,
  };
}
