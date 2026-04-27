import type { FindingV0 } from '@critiq/core-finding-schema';

import type { CheckReportFinding, CheckRuleSummary } from './shared';

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
  findings: ReadonlyArray<Pick<CheckReportFinding, 'rule' | 'severity'>>,
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

export function compactFindingForReport(
  finding: FindingV0,
): CheckReportFinding {
  const detailAttribute = finding.attributes?.['detail'];
  const detail =
    typeof detailAttribute === 'string' && detailAttribute.trim().length > 0
      ? detailAttribute
      : undefined;

  return {
    schemaVersion: finding.schemaVersion,
    findingId: finding.findingId,
    rule: finding.rule,
    title: finding.title,
    summary: finding.summary,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence,
    tags: finding.tags,
    locations: finding.locations,
    evidence: finding.evidence,
    remediation: finding.remediation,
    fingerprints: {
      primary: finding.fingerprints.primary,
    },
    ...(detail
      ? {
          attributes: {
            detail,
          },
        }
      : {}),
  };
}

export function dedupeReportFindings(
  findings: readonly CheckReportFinding[],
): CheckReportFinding[] {
  const dedupedFindings: CheckReportFinding[] = [];
  const seenKeys = new Set<string>();

  for (const finding of findings) {
    const key = JSON.stringify({
      schemaVersion: finding.schemaVersion,
      rule: finding.rule,
      title: finding.title,
      summary: finding.summary,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      tags: finding.tags,
      locations: finding.locations,
      evidence: finding.evidence,
      remediation: finding.remediation,
      attributes: finding.attributes,
    });

    if (seenKeys.has(key)) {
      continue;
    }

    seenKeys.add(key);
    dedupedFindings.push(finding);
  }

  return dedupedFindings;
}
