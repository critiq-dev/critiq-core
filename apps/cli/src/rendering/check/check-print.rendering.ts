import { formatDiagnosticsForTerminal } from '@critiq/core-diagnostics';
import {
  type CheckCommandEnvelope,
  type CheckOverallRuleResult,
  type CheckReportFinding,
  type CheckSecretsScanFinding,
} from '@critiq/check-runner';

import { humanizeRuleId } from '../../utils/humanize-rule-id.util';
import { colorize, renderFindingCodeFrame, terminalAnsi } from './terminal-frames.rendering';

const ansi = terminalAnsi;

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
