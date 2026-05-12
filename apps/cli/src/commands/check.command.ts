import {
  runCheckCommand,
  runSecretsScan,
  toCheckSecretsScanPayload,
} from '@critiq/check-runner';
import { formatDiagnosticsForTerminal } from '@critiq/core-diagnostics';

import { type CliRuntime, type OutputFormat } from '../cli.types';
import { renderCheckHtml } from '../rendering/check/check-html.rendering';
import { renderCheckJson } from '../rendering/check/check-json.rendering';
import { renderCheckPretty } from '../rendering/check/check-print.rendering';
import { renderCheckSarif } from '../rendering/check/check-sarif.rendering';
import {
  createScanProgressRenderer,
} from '../rendering/check.rendering';

export function handleCheck(
  target: string | undefined,
  format: OutputFormat,
  runtime: Required<CliRuntime>,
  baseRef?: string,
  headRef?: string,
  staged = false,
): number {
  const progressRenderer =
    format === 'pretty' ? createScanProgressRenderer(runtime) : null;
  const runnerFormat = format === 'pretty' ? 'pretty' : 'json';
  const result = runCheckCommand({
    cwd: runtime.cwd,
    target,
    format: runnerFormat,
    baseRef,
    headRef,
    catalogResolverBasePaths: [runtime.cwd],
    onProgress: progressRenderer
      ? (update) => {
          progressRenderer.update(update);
        }
      : undefined,
  });
  progressRenderer?.stop();

  const secretsResult = runSecretsScan({
    cwd: runtime.cwd,
    target,
    baseRef,
    headRef,
    staged,
    failOnFindings: false,
  });
  const secretsPayload = toCheckSecretsScanPayload(secretsResult);
  const envelopeWithSecrets = {
    ...result.envelope,
    secretsScan: secretsPayload,
  };

  if (format === 'json') {
    runtime.writeStdout(renderCheckJson(envelopeWithSecrets));
  } else if (format === 'sarif') {
    runtime.writeStdout(renderCheckSarif(envelopeWithSecrets));
  } else if (format === 'html') {
    runtime.writeStdout(renderCheckHtml(envelopeWithSecrets));
  } else if (
    result.envelope.exitCode > 0 &&
    result.envelope.findingCount === 0
  ) {
    runtime.writeStderr(
      formatDiagnosticsForTerminal(result.envelope.diagnostics),
    );
  } else {
    runtime.writeStdout(
      renderCheckPretty(
        envelopeWithSecrets,
        result.overallRuleResults,
        result.sourceTextsByPath,
      ),
    );
  }

  return result.envelope.exitCode;
}
