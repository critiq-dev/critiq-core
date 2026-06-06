import {
  runCheckCommand,
  runSecretsScan,
  toCheckSecretsScanPayload,
} from '@critiq/check-runner';
import { formatDiagnosticsForTerminal } from '@critiq/core-diagnostics';

import { type RequiredCliRuntime, type OutputFormat } from '../cli.types';
import { renderCheckHtml } from '../rendering/check/check-html.rendering';
import { renderCheckJson } from '../rendering/check/check-json.rendering';
import { renderCheckPretty } from '../rendering/check/check-print.rendering';
import { renderCheckSarif } from '../rendering/check/check-sarif.rendering';
import {
  createScanProgressRenderer,
} from '../rendering/check.rendering';
import { ensureCatalogPackageForCheck } from '../utils/ensure-catalog-package.util';

export async function handleCheck(
  target: string | undefined,
  format: OutputFormat,
  runtime: RequiredCliRuntime,
  baseRef?: string,
  headRef?: string,
  staged = false,
): Promise<number> {
  const catalogEnsure = await ensureCatalogPackageForCheck(runtime, format);

  if (catalogEnsure.ok === false) {
    runtime.writeStderr(catalogEnsure.message);
    return catalogEnsure.exitCode;
  }

  const progressRenderer =
    format === 'pretty' ? createScanProgressRenderer(runtime) : null;
  const runnerFormat = format === 'pretty' ? 'pretty' : 'json';
  const result = runCheckCommand({
    cwd: runtime.cwd,
    target,
    format: runnerFormat,
    baseRef,
    headRef,
    catalogResolverBasePaths: catalogEnsure.catalogResolverBasePaths ?? [
      runtime.cwd,
    ],
    catalogPackageRoots: catalogEnsure.catalogPackageRoots,
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
