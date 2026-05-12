import { formatDiagnosticsForTerminal } from '@critiq/core-diagnostics';
import {
  type CheckProgressUpdate,
  type CheckReportFinding,
  type RunSecretsScanResult,
} from '@critiq/check-runner';

import { type CliRuntime } from '../cli.types';
import { colorize, renderFindingCodeFrame, terminalAnsi } from './check/terminal-frames.rendering';

const ansi = terminalAnsi;

const scanBanner = [
  `                                                               `,
  `  ▄█████ ▄▄▄▄  ▄▄ ▄▄▄▄▄▄ ▄▄  ▄▄▄    ▄█████  ▄▄▄▄  ▄▄▄  ▄▄  ▄▄  `,
  `  ██     ██▄█▄ ██   ██   ██ ██▀██   ▀▀▀▄▄▄ ██▀▀▀ ██▀██ ███▄██  `,
  `  ▀█████ ██ ██ ██   ██   ██ ▀███▀   █████▀ ▀████ ██▀██ ██ ▀██  `,
  `                               ▀▀                              `,
  ``,
  `Increase the confidence in the code you ship`,
  `Visit https://critiq.dev for more features and docs`,
];

function renderProgressBar(
  completed: number,
  total: number,
  width = 28,
): string {
  const safeTotal = Math.max(total, 1);
  const clampedCompleted = Math.max(0, Math.min(completed, safeTotal));
  const filledWidth = Math.round((clampedCompleted / safeTotal) * width);

  return `[${'#'.repeat(filledWidth)}${'-'.repeat(width - filledWidth)}]`;
}

function progressStepLabel(step: CheckProgressUpdate['step']): string {
  switch (step) {
    case 'preparing':
      return 'Preparing scan';
    case 'scanning':
      return 'Scanning files';
    case 'finalizing':
      return 'Finalizing results';
  }
}

function renderScanProgress(update: CheckProgressUpdate): string {
  const detail =
    update.currentFilePath && update.step === 'scanning'
      ? `Current: ${update.currentFilePath}`
      : `Current: ${progressStepLabel(update.step)}`;

  return [
    ...scanBanner,
    '',
    'Critiq Scan',
    `Step: ${progressStepLabel(update.step)}`,
    `Progress: ${renderProgressBar(update.scannedFileCount, update.totalFileCount)} ${update.scannedFileCount}/${update.totalFileCount}`,
    detail,
  ].join('\n');
}

export function createScanProgressRenderer(runtime: Required<CliRuntime>) {
  let lineCount = 0;
  let active = false;

  return {
    update(update: CheckProgressUpdate) {
      if (!runtime.isInteractive) {
        return;
      }

      const frame = `${renderScanProgress(update)}\n`;

      if (!active) {
        runtime.writeRaw('\u001b[?25l');
        active = true;
      } else if (lineCount > 0) {
        runtime.writeRaw(`\u001b[${lineCount}F`);
      }

      runtime.writeRaw('\u001b[J');
      runtime.writeRaw(frame);
      lineCount = frame.split('\n').length - 1;
    },
    stop() {
      if (!active) {
        return;
      }

      if (lineCount > 0) {
        runtime.writeRaw(`\u001b[${lineCount}F`);
      }

      runtime.writeRaw('\u001b[J\u001b[?25h');
      active = false;
      lineCount = 0;
    },
  };
}

export { renderCheckPretty } from './check/check-print.rendering';

export function renderAuditSecretsPretty(
  result: RunSecretsScanResult,
  sourceTextsByPath: ReadonlyMap<string, string>,
): string {
  const lines: string[] = [
    '',
    `${ansi.bold}Secret scan${ansi.reset} ${colorize('dim', '(critiq audit secrets)')}`,
    '',
  ];

  if (result.scope.mode === 'diff') {
    lines.push(
      `Scope: diff (${result.scope.base}..${result.scope.head})`,
      `Changed files (pre-filter): ${String(result.scope.changedFileCount ?? 0)}`,
      '',
    );
  }

  if (result.findingCount === 0) {
    lines.push(
      `${colorize('green', 'PASS', { bold: true })} No obvious secret patterns detected in ${String(result.scannedFileCount)} scanned file(s).`,
    );
  } else {
    lines.push(
      `${colorize('red', 'FAIL', { bold: true })} ${String(result.findingCount)} possible secret pattern(s) in ${String(result.scannedFileCount)} scanned file(s).`,
    );
    const findingsByPath = new Map<string, RunSecretsScanResult['findings']>();

    for (const finding of result.findings) {
      const pathKey = finding.locations.primary.path;
      const list = findingsByPath.get(pathKey) ?? [];
      list.push(finding);
      findingsByPath.set(pathKey, list);
    }

    for (const [path, findings] of Array.from(findingsByPath.entries()).sort(
      ([left], [right]) => left.localeCompare(right),
    )) {
      lines.push('', `${colorize('red', `● ${path}`, { bold: true })}`);

      for (const finding of findings) {
        const sourceText = sourceTextsByPath.get(path);
        const loc = finding.locations
          .primary as CheckReportFinding['locations']['primary'];

        lines.push(
          `  ${colorize('red', '✕')} ${finding.detectorId}`,
          `    ${finding.summary}`,
        );

        if (sourceText) {
          lines.push(...renderFindingCodeFrame(sourceText, loc));
        }

        lines.push(
          `    at ${path}:${String(finding.locations.primary.startLine)}:${String(finding.locations.primary.startColumn)}`,
        );
      }
    }
  }

  if (result.diagnostics.length > 0) {
    lines.push(
      '',
      'Diagnostics',
      formatDiagnosticsForTerminal(result.diagnostics),
    );
  }

  lines.push(
    '',
    `Scanned ${String(result.scannedFileCount)} file(s) for secret patterns`,
    `Exit code:   ${String(result.exitCode)}`,
  );

  return lines.join('\n');
}
