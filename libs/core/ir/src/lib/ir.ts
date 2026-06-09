import {
  type RuleAppliesTo,
  type ContractValidatedRuleDocument,
  type RuleConditionNode,
  type RuleDetection,
  type RuleDocumentV0Alpha1,
  type RuleEmit,
  type RuleReference,
  type RuleStability,
  type RuleVulnerability,
  type RuleVulnerabilityAffectedVersion,
  type RuleWhereClause,
} from '@critiq/core-rules-dsl';
import { createHash } from 'node:crypto';

/**
 * Represents a canonical normalized language identifier.
 */
export type CanonicalLanguage =
  | 'typescript'
  | 'javascript'
  | 'python'
  | 'go'
  | 'java'
  | 'php'
  | 'ruby'
  | 'rust'
  | 'sql'
  | 'dockerfile'
  | 'cloudformation';

/**
 * Represents a canonical normalized language identifier plus the catalog-wide
 * `all` selector.
 */
export type NormalizedLanguage =
  | CanonicalLanguage
  | 'all';

/**
 * Represents a normalized predicate comparison operator.
 */
export type NormalizedComparisonOperator =
  | 'equals'
  | 'in'
  | 'matches'
  | 'exists';

/**
 * Represents a single normalized comparison clause.
 */
export interface NormalizedComparison {
  path: string;
  operator: NormalizedComparisonOperator;
  value: string | boolean | string[];
}

/**
 * Represents a normalized structural predicate.
 */
export interface NormalizedStructuralPredicate {
  type: 'node' | 'ancestor' | 'fact';
  kind: string;
  bind?: string;
  where: NormalizedComparison[];
}

/**
 * Represents a normalized predicate tree.
 */
export type NormalizedPredicate =
  | { type: 'all'; conditions: NormalizedPredicate[] }
  | { type: 'any'; conditions: NormalizedPredicate[] }
  | { type: 'not'; condition: NormalizedPredicate }
  | NormalizedStructuralPredicate;

/**
 * Represents the normalized rule scope.
 */
export interface NormalizedScope {
  languages: NormalizedLanguage[];
  includeGlobs: string[];
  excludeGlobs: string[];
  changedLinesOnly: boolean;
}

/**
 * Represents a normalized template-bearing field.
 */
export interface NormalizedTemplateField {
  raw: string;
}

/**
 * Represents the normalized emit specification.
 */
export interface NormalizedEmitSpec {
  finding: {
    category: RuleEmit['finding']['category'];
    severity: RuleEmit['finding']['severity'];
    confidence: RuleEmit['finding']['confidence'];
    tags: string[];
  };
  message: {
    title: NormalizedTemplateField;
    summary: NormalizedTemplateField;
    detail?: NormalizedTemplateField;
  };
  remediation?: {
    summary: NormalizedTemplateField;
  };
}

/**
 * Represents the canonical normalized rule consumed by the runtime.
 */
export interface NormalizedRule {
  apiVersion: 'critiq.dev/v1alpha1';
  kind: 'Rule';
  ruleId: string;
  title: string;
  summary: string;
  rationale?: string;
  status?: string;
  stability?: RuleStability;
  appliesTo?: RuleAppliesTo;
  tags: string[];
  aliases: string[];
  references: RuleReference[];
  detection?: RuleDetection;
  vulnerability?: RuleVulnerability;
  scope: NormalizedScope;
  predicate: NormalizedPredicate;
  emit: NormalizedEmitSpec;
  ruleHash: string;
}

/**
 * Fields hashed for stable finding fingerprints. Transparency metadata is excluded.
 */
export interface NormalizedRuleFingerprintMaterial {
  ruleId: string;
  scope: NormalizedScope;
  predicate: NormalizedPredicate;
  emit: NormalizedEmitSpec;
}

/**
 * Represents optional source/debug metadata preserved alongside the canonical IR.
 */
export interface NormalizedRuleDebugSidecar {
  uri: string;
  sourceMap: ContractValidatedRuleDocument['sourceMap'];
}

/**
 * Represents the result of normalizing a validated rule document.
 */
export interface NormalizeRuleDocumentResult {
  rule: NormalizedRule;
  ruleHash: string;
  debug: NormalizedRuleDebugSidecar;
}

function normalizeLanguage(language: string): NormalizedLanguage {
  if (language === 'ts' || language === 'typescript') {
    return 'typescript';
  }

  if (language === 'js' || language === 'javascript') {
    return 'javascript';
  }

  if (language === 'python') {
    return 'python';
  }

  if (language === 'go') {
    return 'go';
  }

  if (language === 'java') {
    return 'java';
  }

  if (language === 'php') {
    return 'php';
  }

  if (language === 'ruby') {
    return 'ruby';
  }

  if (language === 'rust') {
    return 'rust';
  }

  return 'all';
}

function normalizeStringArray(values: readonly string[] | undefined): string[] {
  if (!values) {
    return [];
  }

  return Array.from(
    new Set(
      values
        .map((value) => value.trim())
        .filter((value) => value.length > 0),
    ),
  ).sort();
}

function normalizeTemplateField(value: string): NormalizedTemplateField {
  return {
    raw: value,
  };
}

function normalizeWhereClause(whereClause: RuleWhereClause): NormalizedComparison {
  if ('equals' in whereClause) {
    return {
      path: whereClause.path,
      operator: 'equals',
      value: whereClause.equals,
    };
  }

  if ('in' in whereClause) {
    return {
      path: whereClause.path,
      operator: 'in',
      value: [...whereClause.in],
    };
  }

  if ('matches' in whereClause) {
    return {
      path: whereClause.path,
      operator: 'matches',
      value: whereClause.matches,
    };
  }

  return {
    path: whereClause.path,
    operator: 'exists',
    value: 'exists' in whereClause ? whereClause.exists : false,
  };
}

function normalizePredicate(condition: RuleConditionNode): NormalizedPredicate {
  if ('all' in condition) {
    return {
      type: 'all',
      conditions: condition.all.map(normalizePredicate),
    };
  }

  if ('any' in condition) {
    return {
      type: 'any',
      conditions: condition.any.map(normalizePredicate),
    };
  }

  if ('not' in condition) {
    return {
      type: 'not',
      condition: normalizePredicate(condition.not),
    };
  }

  const predicate = 'node' in condition
    ? condition.node
    : 'ancestor' in condition
      ? condition.ancestor
      : condition.fact;

  return {
    type: 'node' in condition
      ? 'node'
      : 'ancestor' in condition
        ? 'ancestor'
        : 'fact',
    kind: predicate.kind,
    bind: predicate.bind,
    where: (predicate.where ?? []).map(normalizeWhereClause),
  };
}

function normalizeRuleEmit(emit: RuleEmit): NormalizedEmitSpec {
  return {
    finding: {
      category: emit.finding.category,
      severity: emit.finding.severity,
      confidence: emit.finding.confidence,
      tags: normalizeStringArray(emit.finding.tags),
    },
    message: {
      title: normalizeTemplateField(emit.message.title),
      summary: normalizeTemplateField(emit.message.summary),
      detail: emit.message.detail
        ? normalizeTemplateField(emit.message.detail)
        : undefined,
    },
    remediation: emit.remediation
      ? {
          summary: normalizeTemplateField(emit.remediation.summary),
        }
      : undefined,
  };
}

function affectedVersionSortKey(
  entry: RuleVulnerabilityAffectedVersion,
): string {
  if (entry.kind === 'exact') {
    return `0:${entry.version}`;
  }

  if (entry.kind === 'range') {
    return `1:${entry.expression}`;
  }

  return '2:all';
}

function normalizeAffectedVersions(
  entries: readonly RuleVulnerabilityAffectedVersion[],
): RuleVulnerabilityAffectedVersion[] {
  return [...entries].sort((left, right) =>
    affectedVersionSortKey(left).localeCompare(affectedVersionSortKey(right)),
  );
}

function normalizeReferences(
  references: readonly RuleReference[] | undefined,
): RuleReference[] {
  if (!references) {
    return [];
  }

  return [...references].sort((left, right) =>
    referenceSortKey(left).localeCompare(referenceSortKey(right)),
  );
}

function referenceSortKey(reference: RuleReference): string {
  return [
    reference.kind,
    reference.id ?? '',
    reference.url ?? '',
    reference.title ?? '',
  ].join(':');
}

function normalizeVulnerability(
  vulnerability: RuleVulnerability | undefined,
): RuleVulnerability | undefined {
  if (!vulnerability) {
    return undefined;
  }

  const normalizedIds = vulnerability.ids
    ? {
        ...(normalizeStringArray(vulnerability.ids.cve).length > 0
          ? { cve: normalizeStringArray(vulnerability.ids.cve) }
          : {}),
        ...(normalizeStringArray(vulnerability.ids.cwe).length > 0
          ? { cwe: normalizeStringArray(vulnerability.ids.cwe) }
          : {}),
        ...(normalizeStringArray(vulnerability.ids.advisory).length > 0
          ? { advisory: normalizeStringArray(vulnerability.ids.advisory) }
          : {}),
        ...(vulnerability.ids.external?.length
          ? {
              external: [...vulnerability.ids.external].sort((left, right) =>
                `${left.source}:${left.id}`.localeCompare(
                  `${right.source}:${right.id}`,
                ),
              ),
            }
          : {}),
      }
    : undefined;

  return {
    ...vulnerability,
    labels: vulnerability.labels
      ? [...vulnerability.labels].sort((left, right) => left.localeCompare(right))
      : undefined,
    ids:
      normalizedIds && Object.keys(normalizedIds).length > 0
        ? normalizedIds
        : undefined,
    package: {
      ...vulnerability.package,
      affectedVersions: normalizeAffectedVersions(
        vulnerability.package.affectedVersions,
      ),
    },
    credit: normalizeStringArray(vulnerability.credit),
    fix: {
      ...vulnerability.fix,
      versions: normalizeStringArray(vulnerability.fix.versions),
    },
    severity: vulnerability.severity?.cvss
      ? {
          cvss: [...vulnerability.severity.cvss].sort((left, right) =>
            left.version.localeCompare(right.version),
          ),
        }
      : vulnerability.severity,
  };
}

function buildFingerprintMaterial(
  normalizedRule: Omit<NormalizedRule, 'ruleHash'>,
): NormalizedRuleFingerprintMaterial {
  return {
    ruleId: normalizedRule.ruleId,
    scope: normalizedRule.scope,
    predicate: normalizedRule.predicate,
    emit: normalizedRule.emit,
  };
}

function stableSerialize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableSerialize).join(',')}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey));

  return `{${entries
    .map(([key, entryValue]) => `${JSON.stringify(key)}:${stableSerialize(entryValue)}`)
    .join(',')}}`;
}

function hashNormalizedRule(
  normalizedRule: Omit<NormalizedRule, 'ruleHash'>,
): string {
  return createHash('sha256')
    .update(stableSerialize(buildFingerprintMaterial(normalizedRule)))
    .digest('hex');
}

function normalizeRuleDocumentShape(
  document: RuleDocumentV0Alpha1,
): Omit<NormalizedRule, 'ruleHash'> {
  return {
    apiVersion: document.apiVersion,
    kind: document.kind,
    ruleId: document.metadata.id,
    title: document.metadata.title,
    summary: document.metadata.summary,
    rationale: document.metadata.rationale,
    status: document.metadata.status,
    stability: document.metadata.stability,
    appliesTo: document.metadata.appliesTo,
    tags: normalizeStringArray(document.metadata.tags),
    aliases: normalizeStringArray(document.metadata.aliases),
    references: normalizeReferences(document.metadata.references),
    detection: document.metadata.detection,
    vulnerability: normalizeVulnerability(document.vulnerability),
    scope: {
      languages: Array.from(
        new Set(document.scope.languages.map(normalizeLanguage)),
      ).sort() as NormalizedLanguage[],
      includeGlobs: normalizeStringArray(document.scope.paths?.include),
      excludeGlobs: normalizeStringArray(document.scope.paths?.exclude),
      changedLinesOnly: document.scope.changedLinesOnly ?? false,
    },
    predicate: normalizePredicate(document.match),
    emit: normalizeRuleEmit(document.emit),
  };
}

/**
 * Normalizes a contract-valid semantic-valid rule document into the canonical IR.
 */
export function normalizeRuleDocument(
  validatedRuleDocument: ContractValidatedRuleDocument,
): NormalizeRuleDocumentResult {
  const normalizedRuleWithoutHash = normalizeRuleDocumentShape(
    validatedRuleDocument.document,
  );
  const ruleHash = hashNormalizedRule(normalizedRuleWithoutHash);
  const normalizedRule: NormalizedRule = {
    ...normalizedRuleWithoutHash,
    ruleHash,
  };

  return {
    rule: normalizedRule,
    ruleHash,
    debug: {
      uri: validatedRuleDocument.uri,
      sourceMap: validatedRuleDocument.sourceMap,
    },
  };
}
