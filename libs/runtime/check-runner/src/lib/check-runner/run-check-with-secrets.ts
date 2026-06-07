import { type Diagnostic } from '@critiq/core-diagnostics';

import {
  determineExitCode,
  type CheckCommandEnvelope,
  type RunCheckCommandResult,
} from './shared';
import { runCheckCommand, type RunCheckCommandOptions } from './runtime';
import { buildScanContext, collectPreloadPaths } from './scan-context';
import { ScanPhaseTimer, type CheckScanProfile } from './scan-profile';
import { runSecretsScan, toCheckSecretsScanPayload } from '../secrets-scanner/run-secrets-scan';
import type { RunSecretsScanOptions } from '../secrets-scanner/types';

export interface RunCheckWithSecretsOptions
  extends Omit<RunCheckCommandOptions, 'profile' | 'scanContext'>,
    Pick<
      RunSecretsScanOptions,
      'staged' | 'includeTests' | 'ignorePaths' | 'failOnFindings'
    > {
  enableProfile?: boolean;
}

export interface RunCheckWithSecretsResult {
  check: RunCheckCommandResult;
  profile?: CheckScanProfile;
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
  const timer = options.enableProfile ? new ScanPhaseTimer() : undefined;
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
  await scanContext.preloadFiles(collectPreloadPaths(scanContext));
  timer?.mark('preload:end');

  timer?.mark('secrets:start');

  const promiseCheck = Promise.resolve().then(() => {
    const r = runCheckCommand({
      ...checkOptions,
      scanContext,
      profile: timer,
    });
    return r;
  });
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

  const secretsPayload = toCheckSecretsScanPayload(secretsResult);
  const envelope: CheckCommandEnvelope = {
    ...check.envelope,
    secretsScan: secretsPayload,
    profile: timer?.finish(),
  };

  return {
    check: {
      ...check,
      envelope,
    },
    profile: envelope.profile,
  };
}
