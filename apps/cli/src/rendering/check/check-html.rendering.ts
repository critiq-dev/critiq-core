import { type CheckCommandEnvelope } from '@critiq/check-runner';

import { isFindingSuppressed } from './check-finding.util';

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function renderCheckHtml(envelope: CheckCommandEnvelope): string {
  const rows = envelope.findings
    .map((finding) => {
      const suppressed = isFindingSuppressed(finding) ? 'yes' : 'no';
      const remediation = finding.remediation?.summary ?? '';
      const detail = finding.attributes?.detail ?? '';
      const location = `${finding.locations.primary.path}:${finding.locations.primary.startLine}:${finding.locations.primary.startColumn}`;
      return `<tr><td>${escapeHtml(finding.rule.id)}</td><td>${escapeHtml(finding.severity)}</td><td>${escapeHtml(location)}</td><td>${escapeHtml(finding.summary)}</td><td>${escapeHtml(remediation)}</td><td>${escapeHtml(String(suppressed))}</td><td><code>${escapeHtml(finding.fingerprints.primary)}</code></td><td><code>${escapeHtml(
        JSON.stringify(envelope.provenance),
      )}</code>${detail.length > 0 ? `<br /><small>${escapeHtml(detail)}</small>` : ''}</td></tr>`;
    })
    .join('\n');

  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '  <meta charset="utf-8" />',
    '  <meta name="viewport" content="width=device-width, initial-scale=1" />',
    '  <title>Critiq Check Report</title>',
    '  <style>',
    '    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 24px; color: #111827; }',
    '    h1 { margin-bottom: 0.2rem; }',
    '    .meta { color: #4b5563; margin-bottom: 1rem; }',
    '    table { border-collapse: collapse; width: 100%; font-size: 14px; }',
    '    th, td { border: 1px solid #d1d5db; text-align: left; vertical-align: top; padding: 8px; }',
    '    th { background: #f3f4f6; }',
    '    code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }',
    '  </style>',
    '</head>',
    '<body>',
    '  <h1>Critiq Check Report</h1>',
    `  <p class="meta">Target: ${escapeHtml(envelope.target)} | Findings: ${escapeHtml(String(envelope.findingCount))} | Scanned files: ${escapeHtml(
      String(envelope.scannedFileCount),
    )} | Generated: ${escapeHtml(envelope.provenance.generatedAt)}</p>`,
    '  <table>',
    '    <thead>',
    '      <tr><th>Rule</th><th>Severity</th><th>Location</th><th>Summary</th><th>Remediation</th><th>Suppressed</th><th>Fingerprint</th><th>Provenance</th></tr>',
    '    </thead>',
    '    <tbody>',
    rows.length > 0
      ? rows
      : '<tr><td colspan="8">No findings.</td></tr>',
    '    </tbody>',
    '  </table>',
    '</body>',
    '</html>',
  ].join('\n');
}
