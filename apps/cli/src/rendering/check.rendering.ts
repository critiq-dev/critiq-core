import { formatDiagnosticsForTerminal } from '@critiq/core-diagnostics';
import {
  type CheckCommandEnvelope,
  type CheckOverallRuleResult,
  type CheckProgressUpdate,
  type CheckReportFinding,
  type CheckSecretsScanFinding,
  type RunSecretsScanResult,
} from '@critiq/check-runner';

import { type CliRuntime } from '../cli.types';
import { humanizeRuleId } from '../utils/humanize-rule-id.util';

const ansi = {
  reset: '\u001b[0m',
  red: '\u001b[31m',
  green: '\u001b[32m',
  dim: '\u001b[2m',
  bold: '\u001b[1m',
};

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

function colorize(
  color: keyof typeof ansi,
  value: string,
  options: { bold?: boolean } = {},
): string {
  const prefixes = [options.bold ? ansi.bold : '', ansi[color]].join('');

  return `${prefixes}${value}${ansi.reset}`;
}

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

function renderFindingCodeFrame(
  sourceText: string,
  location: CheckReportFinding['locations']['primary'],
): string[] {
  const lines = sourceText.split(/\r?\n/);
  const lineNumberWidth = String(location.endLine + 1).length;
  const startLine = Math.max(location.startLine - 1, 1);
  const highlightedLineCount = location.endLine - location.startLine + 1;
  const maxHighlightedLines = 3;
  const truncated =
    Number.isFinite(highlightedLineCount) &&
    highlightedLineCount > maxHighlightedLines;
  const renderedHighlightEndLine = truncated
    ? location.startLine + maxHighlightedLines - 1
    : location.endLine;
  const endLine = Math.min(renderedHighlightEndLine + 1, lines.length);
  const frameLines: string[] = [];

  for (let lineNumber = startLine; lineNumber <= endLine; lineNumber += 1) {
    const lineText = lines[lineNumber - 1] ?? '';
    const marker = lineNumber === location.startLine ? '>' : ' ';

    frameLines.push(
      `    ${marker} ${String(lineNumber).padStart(lineNumberWidth, ' ')} | ${lineText}`,
    );

    if (lineNumber === location.startLine) {
      const caretStart = Math.max(location.startColumn, 1);
      const caretWidth = Math.max(
        1,
        lineNumber === location.endLine
          ? location.endColumn - location.startColumn
          : Math.max(lineText.length - location.startColumn + 2, 1),
      );

      frameLines.push(
        `      ${' '.repeat(lineNumberWidth)} | ${' '.repeat(caretStart - 1)}${'^'.repeat(caretWidth)}`,
      );
    }
  }

  if (truncated) {
    frameLines.push(
      `      ${' '.repeat(lineNumberWidth)} | ${colorize('dim', `... ${location.endLine - renderedHighlightEndLine} more line(s) omitted`)}`,
    );
  }

  return frameLines;
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

export function renderCheckPretty(
  envelope: CheckCommandEnvelope,
  overallRuleResults: readonly CheckOverallRuleResult[],
  sourceTextsByPath: ReadonlyMap<string, string>,
): string {
  const overallStatus = overallRuleResults.every(
    (result) => result.status === 'passed',
  )
    ? 'PASS'
    : 'FAIL';

  const secrets = envelope.secretsScan;
  const lines: string[] = [''];

  if (secrets) {
    lines.push(
      `${ansi.bold}Secrets scan${ansi.reset} ${colorize('dim', '(advisory — does not affect exit code)')}`,
    );

    if (secrets.findingCount === 0) {
      lines.push(
        ` ${colorize('green', '✓')} No obvious secret patterns detected in ${String(secrets.scannedFileCount)} scanned file(s).`,
      );
    } else {
      lines.push(
        ` ${colorize('red', '✕')} ${String(secrets.findingCount)} possible secret pattern(s) in ${String(secrets.scannedFileCount)} scanned file(s).`,
      );
      const findingsByPath = new Map<string, CheckSecretsScanFinding[]>();

      for (const finding of secrets.findings) {
        const pathKey = finding.locations.primary.path;
        const list = findingsByPath.get(pathKey) ?? [];
        list.push(finding);
        findingsByPath.set(pathKey, list);
      }

      for (const [path, findings] of Array.from(findingsByPath.entries()).sort(
        ([left], [right]) => left.localeCompare(right),
      )) {
        lines.push(`   ${colorize('red', path, { bold: true })}`);

        for (const finding of findings) {
          lines.push(
            `     ${colorize('dim', finding.detectorId)} — ${finding.summary}`,
            `       at ${path}:${String(finding.locations.primary.startLine)}:${String(finding.locations.primary.startColumn)}`,
          );
        }
      }
    }

    if (secrets.diagnostics.length > 0) {
      lines.push('', formatDiagnosticsForTerminal(secrets.diagnostics));
    }

    lines.push(
      '',
      colorize(
        'dim',
        'Run critiq audit secrets for full output and CI-friendly gating on secret findings.',
      ),
      '',
    );
  }

  lines.push(
    `${colorize(overallStatus === 'PASS' ? 'green' : 'red', overallStatus, { bold: true })} Rule Results`,
  );

  for (const ruleResult of overallRuleResults) {
    lines.push(
      ruleResult.status === 'failed'
        ? ` ${colorize('red', '✕')} ${humanizeRuleId(ruleResult.ruleId)}`
        : ` ${colorize('green', '✓')} ${humanizeRuleId(ruleResult.ruleId)}`,
    );
  }

  if (envelope.findings.length > 0) {
    const findingsByPath = new Map<string, CheckReportFinding[]>();

    for (const finding of envelope.findings) {
      const findingsForPath =
        findingsByPath.get(finding.locations.primary.path) ?? [];
      findingsForPath.push(finding);
      findingsByPath.set(finding.locations.primary.path, findingsForPath);
    }

    for (const [path, findings] of Array.from(findingsByPath.entries()).sort(
      ([left], [right]) => left.localeCompare(right),
    )) {
      lines.push('', `${colorize('red', `● ${path}`, { bold: true })}`);

      for (const finding of findings) {
        const sourceText = sourceTextsByPath.get(
          finding.locations.primary.path,
        );

        lines.push(
          `  ${colorize('red', '✕')} ${humanizeRuleId(finding.rule.id)}`,
          `    ${finding.summary}`,
        );

        if (sourceText) {
          lines.push(
            ...renderFindingCodeFrame(sourceText, finding.locations.primary),
          );
        }

        lines.push(
          `    at ${finding.locations.primary.path}:${finding.locations.primary.startLine}:${finding.locations.primary.startColumn}`,
        );
      }
    }
  }

  if (envelope.diagnostics.length > 0) {
    lines.push(
      '',
      'Diagnostics',
      formatDiagnosticsForTerminal(envelope.diagnostics),
    );
  }

  const failedFileCount = new Set(
    envelope.findings.map((finding) => finding.locations.primary.path),
  ).size;
  const failedRuleCount = overallRuleResults.filter(
    (ruleResult) => ruleResult.status === 'failed',
  ).length;
  const passedRuleCount = Math.max(
    overallRuleResults.length - failedRuleCount,
    0,
  );
  const passedFileCount = Math.max(
    envelope.scannedFileCount - failedFileCount,
    0,
  );

  lines.push(
    '',
    `Checked ${envelope.scannedFileCount} file(s) against ${envelope.matchedRuleCount} rule(s)`,
    `Rules:       ${colorize('red', `${failedRuleCount} failed`, { bold: true })}, ${colorize('green', `${passedRuleCount} passed`, { bold: true })}, ${overallRuleResults.length} total`,
    `Files:       ${colorize('red', `${failedFileCount} failed`, { bold: true })}, ${colorize('green', `${passedFileCount} passed`, { bold: true })}, ${envelope.scannedFileCount} total`,
    `Findings:    ${envelope.findingCount} total`,
    envelope.scope.mode === 'diff'
      ? `Scope:       diff (${envelope.scope.base}..${envelope.scope.head}, ${envelope.scope.changedFileCount} changed file(s))`
      : `Scope:       repo`,
  );

  return lines.join('\n');
}

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
