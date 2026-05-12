import { type CheckCommandEnvelope } from '@critiq/check-runner';

import { isFindingSuppressed } from './check-finding.util';

function toSarifLevel(
  severity: CheckCommandEnvelope['findings'][number]['severity'],
): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

export function renderCheckSarif(envelope: CheckCommandEnvelope): string {
  const rulesById = new Map<string, CheckCommandEnvelope['findings'][number]>();

  for (const finding of envelope.findings) {
    if (!rulesById.has(finding.rule.id)) {
      rulesById.set(finding.rule.id, finding);
    }
  }

  return JSON.stringify(
    {
      $schema:
        'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'critiq-cli',
              informationUri: 'https://critiq.dev',
              version: envelope.provenance.engineVersion,
              rules: Array.from(rulesById.values()).map((finding) => ({
                id: finding.rule.id,
                name: finding.rule.name ?? finding.rule.id,
                shortDescription: {
                  text: finding.title,
                },
                fullDescription: {
                  text: finding.summary,
                },
                help: {
                  text:
                    finding.remediation?.summary ??
                    finding.attributes?.detail ??
                    finding.summary,
                },
                properties: {
                  category: finding.category,
                  tags: finding.tags,
                },
              })),
            },
          },
          results: envelope.findings.map((finding) => ({
            ruleId: finding.rule.id,
            level: toSarifLevel(finding.severity),
            message: {
              text: finding.summary,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: finding.locations.primary.path,
                  },
                  region: {
                    startLine: finding.locations.primary.startLine,
                    startColumn: finding.locations.primary.startColumn,
                    endLine: finding.locations.primary.endLine,
                    endColumn: finding.locations.primary.endColumn,
                  },
                },
              },
            ],
            partialFingerprints: {
              primary: finding.fingerprints.primary,
            },
            suppressions: isFindingSuppressed(finding)
              ? [
                  {
                    kind: 'inSource',
                    status: 'accepted',
                  },
                ]
              : undefined,
            properties: {
              findingId: finding.findingId,
              category: finding.category,
              severity: finding.severity,
              confidence: finding.confidence,
              tags: finding.tags,
              remediation: finding.remediation?.summary ?? null,
              detail: finding.attributes?.detail ?? null,
              suppressed: isFindingSuppressed(finding),
              provenance: envelope.provenance,
            },
          })),
          invocations: [
            {
              executionSuccessful: envelope.exitCode < 2,
              toolExecutionNotifications: envelope.diagnostics.map((diagnostic) => ({
                level:
                  diagnostic.severity === 'error'
                    ? 'error'
                    : diagnostic.severity === 'warning'
                      ? 'warning'
                      : 'note',
                message: {
                  text: diagnostic.message,
                },
                descriptor: {
                  id: diagnostic.code,
                },
              })),
            },
          ],
          properties: {
            critiq: {
              command: envelope.command,
              target: envelope.target,
              scope: envelope.scope,
              matchedRuleCount: envelope.matchedRuleCount,
              scannedFileCount: envelope.scannedFileCount,
              findingCount: envelope.findingCount,
              rulePack: envelope.catalogPackage,
              preset: envelope.preset,
            },
          },
        },
      ],
    },
    null,
    2,
  );
}
