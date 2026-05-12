import {
  resolveCheckTarget,
  runSecretsScan,
  type RunSecretsScanResult,
} from '@critiq/check-runner';
import { formatDiagnosticsForTerminal } from '@critiq/core-diagnostics';
import { readFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';

import { type CliRuntime, type OutputFormat } from '../cli.types';
import { renderAuditSecretsPretty } from '../rendering/check.rendering';
import { renderJson } from '../rendering/rules.rendering';

function collectSourceTextsForFindings(
  displayRoot: string,
  result: RunSecretsScanResult,
): Map<string, string> {
  const paths = new Set<string>();

  for (const finding of result.findings) {
    paths.add(finding.locations.primary.path);
  }

  const map = new Map<string, string>();

  for (const displayPath of paths) {
    const absolutePath = isAbsolute(displayPath)
      ? displayPath
      : resolve(displayRoot, displayPath);

    try {
      map.set(displayPath, readFileSync(absolutePath, 'utf8'));
    } catch {
      // Skip unreadable paths; frames are omitted.
    }
  }

  return map;
}

export function handleAuditSecrets(
  target: string | undefined,
  format: OutputFormat,
  runtime: Required<CliRuntime>,
  baseRef?: string,
  headRef?: string,
): number {
  const resolvedTarget = resolveCheckTarget(runtime.cwd, target ?? '.');

  if (!resolvedTarget.success) {
    runtime.writeStderr(
      formatDiagnosticsForTerminal(
        (resolvedTarget as Extract<typeof resolvedTarget, { success: false }>)
          .diagnostics,
      ),
    );
    return 1;
  }

  const secretsResult = runSecretsScan({
    cwd: runtime.cwd,
    target,
    baseRef,
    headRef,
    failOnFindings: true,
  });

  if (format === 'json') {
    const targetDisplay = target ?? '.';
    runtime.writeStdout(
      renderJson({
        command: 'audit-secrets',
        format: 'json' as const,
        target: targetDisplay,
        ...secretsResult,
      }),
    );
    return secretsResult.exitCode;
  }

  const sourceTexts = collectSourceTextsForFindings(
    resolvedTarget.data.displayRoot,
    secretsResult,
  );

  runtime.writeStdout(renderAuditSecretsPretty(secretsResult, sourceTexts));

  return secretsResult.exitCode;
}
