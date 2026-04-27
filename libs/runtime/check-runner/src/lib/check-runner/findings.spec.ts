import type { FindingV0 } from '@critiq/core-finding-schema';

import {
  compactFindingForReport,
  dedupeReportFindings,
} from './findings';

const finding: FindingV0 = {
  schemaVersion: 'finding/v0',
  findingId: '6d86f84f-3f5c-4bc3-9f5d-8e24d441f8d7',
  rule: {
    id: 'ts.logging.no-console-log',
    name: 'Avoid console.log',
  },
  title: 'Avoid console.log',
  summary: 'Use the project logger instead of console.log.',
  category: 'maintainability',
  severity: 'low',
  confidence: 'high',
  tags: ['logging'],
  locations: {
    primary: {
      path: 'src/example.ts',
      startLine: 1,
      startColumn: 1,
      endLine: 1,
      endColumn: 21,
    },
  },
  evidence: [
    {
      kind: 'match-node',
      label: 'Matched CallExpression',
      path: 'src/example.ts',
      excerpt: 'console.log("hello")',
      range: {
        startLine: 1,
        startColumn: 1,
        endLine: 1,
        endColumn: 21,
      },
    },
  ],
  remediation: {
    summary: 'Replace console.log with the logger.',
  },
  fingerprints: {
    primary: 'sha256:primary',
    logical: 'sha256:logical',
  },
  provenance: {
    engineKind: 'critiq-cli',
    engineVersion: '0.0.1',
    generatedAt: '2026-04-27T10:00:00.000Z',
  },
  attributes: {
    detail: 'additional context',
    ruleHash: 'deadbeef',
    matchSortKey: '000001',
  },
};

describe('check-runner findings helpers', () => {
  it('compacts findings for the json report output', () => {
    expect(compactFindingForReport(finding)).toEqual({
      schemaVersion: 'finding/v0',
      findingId: '6d86f84f-3f5c-4bc3-9f5d-8e24d441f8d7',
      rule: {
        id: 'ts.logging.no-console-log',
        name: 'Avoid console.log',
      },
      title: 'Avoid console.log',
      summary: 'Use the project logger instead of console.log.',
      category: 'maintainability',
      severity: 'low',
      confidence: 'high',
      tags: ['logging'],
      locations: finding.locations,
      evidence: finding.evidence,
      remediation: finding.remediation,
      fingerprints: {
        primary: 'sha256:primary',
      },
      attributes: {
        detail: 'additional context',
      },
    });
  });

  it('dedupes identical report findings even when ids and fingerprints differ', () => {
    const first = compactFindingForReport(finding);
    const second = compactFindingForReport({
      ...finding,
      findingId: 'b9427a0b-1f3b-4a27-bf61-95a4b4fb55fd',
      fingerprints: {
        primary: 'sha256:other-primary',
        logical: 'sha256:other-logical',
      },
      provenance: {
        ...finding.provenance,
        generatedAt: '2026-04-27T11:00:00.000Z',
      },
      attributes: {
        ...finding.attributes,
        ruleHash: 'other-rule-hash',
        matchSortKey: '000002',
      },
    });

    expect(dedupeReportFindings([first, second])).toEqual([first]);
  });
});
