import { type CheckCommandEnvelope } from '@critiq/check-runner';
import { type RuleReference } from '@critiq/core-rules-dsl';

import { isFindingSuppressed } from './check-finding.util';

function readReferences(value: unknown): RuleReference[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter(
    (entry): entry is RuleReference =>
      typeof entry === 'object' &&
      entry !== null &&
      'kind' in entry &&
      typeof (entry as RuleReference).kind === 'string',
  );
}

function primaryReferenceUrl(references: readonly RuleReference[]): string | undefined {
  for (const reference of references) {
    if (reference.url) {
      return reference.url;
    }
  }

  for (const reference of references) {
    if (reference.kind === 'cve' && reference.id) {
      return `https://www.cve.org/CVERecord?id=${encodeURIComponent(reference.id)}`;
    }

    if (reference.kind === 'cwe' && reference.id) {
      const cweNumber = reference.id.replace(/^CWE-/u, '');
      return `https://cwe.mitre.org/data/definitions/${cweNumber}.html`;
    }
  }

  return undefined;
}

function collectTaxonomyTags(finding: CheckCommandEnvelope['findings'][number]): {
  cwe: string[];
  cve: string[];
} {
  const references = readReferences(finding.attributes?.references);
  const vulnerability = finding.attributes?.vulnerability as
    | {
        ids?: {
          cwe?: string[];
          cve?: string[];
        };
      }
    | undefined;
  const cwe = new Set<string>();
  const cve = new Set<string>();

  for (const reference of references) {
    if (reference.kind === 'cwe' && reference.id) {
      cwe.add(reference.id);
    }

    if (reference.kind === 'cve' && reference.id) {
      cve.add(reference.id);
    }
  }

  for (const id of vulnerability?.ids?.cwe ?? []) {
    cwe.add(id);
  }

  for (const id of vulnerability?.ids?.cve ?? []) {
    cve.add(id);
  }

  return {
    cwe: [...cwe].sort((left, right) => left.localeCompare(right)),
    cve: [...cve].sort((left, right) => left.localeCompare(right)),
  };
}

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
              rules: Array.from(rulesById.values()).map((finding) => {
                const references = readReferences(finding.attributes?.references);
                const taxonomy = collectTaxonomyTags(finding);
                const helpUri = primaryReferenceUrl(references);

                return {
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
                  helpUri,
                  relationships: taxonomy.cwe.map((cweId) => ({
                    target: {
                      id: cweId,
                      toolComponent: {
                        name: 'CWE',
                        guid: 'CWE',
                      },
                    },
                    kinds: ['superset'],
                  })),
                  properties: {
                    category: finding.category,
                    tags: finding.tags,
                    cwe: taxonomy.cwe,
                    cve: taxonomy.cve,
                    rationale: finding.attributes?.rationale ?? null,
                  },
                };
              }),
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
              rationale: finding.attributes?.rationale ?? null,
              references: finding.attributes?.references ?? null,
              vulnerability: finding.attributes?.vulnerability ?? null,
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
