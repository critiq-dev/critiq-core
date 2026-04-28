import { runCheckCommand } from '@critiq/check-runner';
import { formatDiagnosticsForTerminal } from '@critiq/core-diagnostics';

import { type CliRuntime, type OutputFormat } from '../cli.types';
import {
  createScanProgressRenderer,
  renderCheckPretty,
} from '../rendering/check.rendering';
import { renderJson } from '../rendering/rules.rendering';

export function handleCheck(
  target: string | undefined,
  format: OutputFormat,
  runtime: Required<CliRuntime>,
  baseRef?: string,
  headRef?: string,
): number {
  const progressRenderer =
    format === 'pretty' ? createScanProgressRenderer(runtime) : null;
  const result = runCheckCommand({
    cwd: runtime.cwd,
    target,
    format,
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

  if (format === 'json') {
    runtime.writeStdout(renderJson(result.envelope));
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
        result.envelope,
        result.overallRuleResults,
        result.sourceTextsByPath,
      ),
    );
  }

  return result.envelope.exitCode;
}
