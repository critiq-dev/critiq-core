import { type CheckCommandEnvelope } from '@critiq/check-runner';

export type CheckReportFindingRow = CheckCommandEnvelope['findings'][number];

export function isFindingSuppressed(finding: CheckReportFindingRow): boolean {
  const attributes = finding.attributes as
    | (Record<string, unknown> & { detail?: string })
    | undefined;

  return attributes?.['suppressed'] === true;
}
