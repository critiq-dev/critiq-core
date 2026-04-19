import type { FindingV0 } from '@critiq/core-finding-schema';

import type { CheckRuleSummary } from './shared';

export function applySeverityOverride(
  finding: FindingV0,
  severityOverride: FindingV0['severity'] | undefined,
): FindingV0 {
  if (!severityOverride || severityOverride === finding.severity) {
    return finding;
  }

  return {
    ...finding,
    severity: severityOverride,
  };
}

export function compareFindings(left: FindingV0, right: FindingV0): number {
  const leftLocation = left.locations.primary;
  const rightLocation = right.locations.primary;

  return (
    leftLocation.path.localeCompare(rightLocation.path) ||
    leftLocation.startLine - rightLocation.startLine ||
    leftLocation.startColumn - rightLocation.startColumn ||
    leftLocation.endLine - rightLocation.endLine ||
    leftLocation.endColumn - rightLocation.endColumn ||
    left.rule.id.localeCompare(right.rule.id) ||
    left.fingerprints.primary.localeCompare(right.fingerprints.primary)
  );
}

export function summarizeFindings(
  findings: readonly FindingV0[],
): CheckRuleSummary[] {
  const summaries = new Map<string, CheckRuleSummary>();

  for (const finding of findings) {
    const summary = summaries.get(finding.rule.id) ?? {
      ruleId: finding.rule.id,
      findingCount: 0,
      severityCounts: {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0,
      },
    };

    summary.findingCount += 1;
    summary.severityCounts[finding.severity] += 1;
    summaries.set(finding.rule.id, summary);
  }

  return Array.from(summaries.values()).sort((left, right) =>
    left.ruleId.localeCompare(right.ruleId),
  );
}
