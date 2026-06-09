import {
  findingCategorySchema,
  findingConfidenceSchema,
  findingSeveritySchema,
  type FindingCategory,
  type FindingConfidence,
  type FindingSeverity,
} from '@critiq/core-finding-schema';
import { z } from 'zod';

const ruleDocumentApiVersion = 'critiq.dev/v1alpha1' as const;
const ruleDocumentKind = 'Rule' as const;

const nonEmptyStringSchema = z.string().min(1);

/**
 * The supported API version for the public v0 alpha rule document contract.
 */
export const RULE_DOCUMENT_V0_ALPHA1_API_VERSION = ruleDocumentApiVersion;

/**
 * The supported kind literal for the public v0 alpha rule document contract.
 */
export const RULE_DOCUMENT_KIND = ruleDocumentKind;

/**
 * Enumerates the rule languages accepted by the v0 alpha contract.
 */
export const ruleLanguageSchema = z.enum([
  'typescript',
  'javascript',
  'ts',
  'js',
  'python',
  'go',
  'java',
  'php',
  'ruby',
  'rust',
  'sql',
  'dockerfile',
  'cloudformation',
  'all',
]);

/**
 * Identifies a language accepted by the v0 alpha rule document contract.
 */
export type RuleLanguage = z.infer<typeof ruleLanguageSchema>;

/**
 * Enumerates the lifecycle stability values accepted by the public contract.
 */
export const ruleStabilitySchema = z.enum(['stable', 'experimental']);

/**
 * Identifies the stability classification accepted by the public contract.
 */
export type RuleStability = z.infer<typeof ruleStabilitySchema>;

/**
 * Enumerates the logical review scopes accepted by the public contract.
 */
export const ruleAppliesToSchema = z.enum([
  'block',
  'function',
  'file',
  'project',
]);

/**
 * Identifies the logical review scope accepted by the public contract.
 */
export type RuleAppliesTo = z.infer<typeof ruleAppliesToSchema>;

/**
 * Enumerates the supported reference kinds for rule citations.
 */
export const ruleReferenceKindSchema = z.enum([
  'internal',
  'url',
  'cwe',
  'cve',
  'owasp',
  'advisory',
]);

/**
 * Identifies a reference kind for rule citations.
 */
export type RuleReferenceKind = z.infer<typeof ruleReferenceKindSchema>;

/**
 * Describes a citation attached to rule metadata.
 */
export const ruleReferenceSchema = z
  .object({
    kind: ruleReferenceKindSchema,
    id: nonEmptyStringSchema.optional(),
    title: nonEmptyStringSchema.optional(),
    url: nonEmptyStringSchema.optional(),
  })
  .strict();

/**
 * Represents a citation attached to rule metadata.
 */
export type RuleReference = z.infer<typeof ruleReferenceSchema>;

/**
 * Enumerates the detection modes accepted by the public contract.
 */
export const ruleDetectionKindSchema = z.enum(['pattern', 'vulnerability']);

/**
 * Identifies the detection mode accepted by the public contract.
 */
export type RuleDetectionKind = z.infer<typeof ruleDetectionKindSchema>;

/**
 * Describes the detection block for a rule document.
 */
export const ruleDetectionSchema = z
  .object({
    kind: ruleDetectionKindSchema,
  })
  .strict();

/**
 * Represents the detection block for a rule document.
 */
export type RuleDetection = z.infer<typeof ruleDetectionSchema>;

/**
 * Enumerates package ecosystems supported by vulnerability metadata.
 */
export const rulePackageEcosystemSchema = z.enum([
  'npm',
  'pypi',
  'maven',
  'go',
  'cargo',
  'nuget',
  'cocoapods',
  'gem',
  'composer',
]);

/**
 * Identifies a package ecosystem in vulnerability metadata.
 */
export type RulePackageEcosystem = z.infer<typeof rulePackageEcosystemSchema>;

/**
 * Describes an exact affected version entry.
 */
export const ruleVulnerabilityAffectedVersionExactSchema = z
  .object({
    kind: z.literal('exact'),
    version: nonEmptyStringSchema,
  })
  .strict();

/**
 * Describes a range affected version entry.
 */
export const ruleVulnerabilityAffectedVersionRangeSchema = z
  .object({
    kind: z.literal('range'),
    expression: nonEmptyStringSchema,
  })
  .strict();

/**
 * Describes an all-versions affected version entry.
 */
export const ruleVulnerabilityAffectedVersionAllSchema = z
  .object({
    kind: z.literal('all'),
  })
  .strict();

/**
 * Describes a single affected-version constraint for vulnerability metadata.
 */
export const ruleVulnerabilityAffectedVersionSchema = z.discriminatedUnion(
  'kind',
  [
    ruleVulnerabilityAffectedVersionExactSchema,
    ruleVulnerabilityAffectedVersionRangeSchema,
    ruleVulnerabilityAffectedVersionAllSchema,
  ],
);

/**
 * Represents a single affected-version constraint for vulnerability metadata.
 */
export type RuleVulnerabilityAffectedVersion = z.infer<
  typeof ruleVulnerabilityAffectedVersionSchema
>;

/**
 * Describes package coordinates in vulnerability metadata.
 */
export const ruleVulnerabilityPackageSchema = z
  .object({
    ecosystem: rulePackageEcosystemSchema,
    namespace: nonEmptyStringSchema.optional(),
    name: nonEmptyStringSchema,
    description: nonEmptyStringSchema.optional(),
    affectedVersions: z.array(ruleVulnerabilityAffectedVersionSchema).min(1),
  })
  .strict();

/**
 * Represents package coordinates in vulnerability metadata.
 */
export type RuleVulnerabilityPackage = z.infer<
  typeof ruleVulnerabilityPackageSchema
>;

/**
 * Describes external vulnerability identifiers.
 */
export const ruleVulnerabilityExternalIdSchema = z
  .object({
    source: nonEmptyStringSchema,
    id: nonEmptyStringSchema,
  })
  .strict();

/**
 * Describes vulnerability identifier groups.
 */
export const ruleVulnerabilityIdsSchema = z
  .object({
    cve: z.array(nonEmptyStringSchema).optional(),
    cwe: z.array(nonEmptyStringSchema).optional(),
    advisory: z.array(nonEmptyStringSchema).optional(),
    external: z.array(ruleVulnerabilityExternalIdSchema).optional(),
  })
  .strict();

/**
 * Describes vulnerability timeline metadata.
 */
export const ruleVulnerabilityTimelineSchema = z
  .object({
    disclosed: nonEmptyStringSchema.optional(),
    published: nonEmptyStringSchema.optional(),
  })
  .strict();

/**
 * Describes a CVSS score entry in vulnerability metadata.
 */
export const ruleVulnerabilityCvssSchema = z
  .object({
    version: nonEmptyStringSchema,
    score: z.number(),
    vector: nonEmptyStringSchema,
  })
  .strict();

/**
 * Describes vulnerability severity metadata.
 */
export const ruleVulnerabilitySeveritySchema = z
  .object({
    cvss: z.array(ruleVulnerabilityCvssSchema).optional(),
  })
  .strict();

/**
 * Describes EPSS threat intelligence metadata.
 */
export const ruleVulnerabilityEpssSchema = z
  .object({
    score: z.number(),
    percentile: z.number().optional(),
  })
  .strict();

/**
 * Describes threat intelligence metadata for a vulnerability.
 */
export const ruleVulnerabilityThreatSchema = z
  .object({
    epss: ruleVulnerabilityEpssSchema.optional(),
  })
  .strict();

/**
 * Enumerates exploit maturity values for vulnerability metadata.
 */
export const ruleVulnerabilityExploitMaturitySchema = z.enum([
  'none',
  'poc',
  'functional',
  'in-the-wild',
  'attacked',
]);

/**
 * Describes exploit metadata for a vulnerability.
 */
export const ruleVulnerabilityExploitSchema = z
  .object({
    maturity: ruleVulnerabilityExploitMaturitySchema,
  })
  .strict();

/**
 * Enumerates vulnerability fix strategies.
 */
export const ruleVulnerabilityFixKindSchema = z.enum([
  'upgrade',
  'remove',
  'pin',
  'mitigate',
  'none',
]);

/**
 * Describes remediation guidance for a tracked vulnerability.
 */
export const ruleVulnerabilityFixSchema = z
  .object({
    kind: ruleVulnerabilityFixKindSchema,
    available: z.boolean(),
    summary: nonEmptyStringSchema,
    versions: z.array(nonEmptyStringSchema).optional(),
  })
  .strict();

/**
 * Describes supply-chain incident metadata for malicious package rules.
 */
export const ruleVulnerabilityIncidentSchema = z
  .object({
    notice: nonEmptyStringSchema.optional(),
    behavior: nonEmptyStringSchema.optional(),
    trackingUrl: nonEmptyStringSchema.optional(),
    ongoing: z.boolean().optional(),
  })
  .strict();

/**
 * Enumerates vulnerability label values.
 */
export const ruleVulnerabilityLabelSchema = z.enum(['new', 'malicious', 'kev']);

/**
 * Enumerates vulnerability issue kinds.
 */
export const ruleVulnerabilityIssueKindSchema = z.enum([
  'cve',
  'malicious',
  'advisory',
]);

/**
 * Describes the vulnerability block for package/CVE tracking rules.
 */
export const ruleVulnerabilitySchema = z
  .object({
    classification: nonEmptyStringSchema,
    issueKind: ruleVulnerabilityIssueKindSchema,
    labels: z.array(ruleVulnerabilityLabelSchema).optional(),
    overview: nonEmptyStringSchema.optional(),
    ids: ruleVulnerabilityIdsSchema.optional(),
    package: ruleVulnerabilityPackageSchema,
    timeline: ruleVulnerabilityTimelineSchema.optional(),
    severity: ruleVulnerabilitySeveritySchema.optional(),
    threat: ruleVulnerabilityThreatSchema.optional(),
    exploit: ruleVulnerabilityExploitSchema.optional(),
    credit: z.array(nonEmptyStringSchema).optional(),
    workaround: nonEmptyStringSchema.optional(),
    fix: ruleVulnerabilityFixSchema,
    incident: ruleVulnerabilityIncidentSchema.optional(),
  })
  .strict();

/**
 * Represents the vulnerability block for package/CVE tracking rules.
 */
export type RuleVulnerability = z.infer<typeof ruleVulnerabilitySchema>;

/**
 * Describes the metadata block for a rule document.
 */
export const ruleMetadataSchema = z
  .object({
    id: nonEmptyStringSchema,
    title: nonEmptyStringSchema,
    summary: nonEmptyStringSchema,
    rationale: nonEmptyStringSchema.optional(),
    tags: z.array(nonEmptyStringSchema).optional(),
    status: nonEmptyStringSchema.optional(),
    stability: ruleStabilitySchema.optional(),
    appliesTo: ruleAppliesToSchema.optional(),
    aliases: z.array(nonEmptyStringSchema).optional(),
    references: z.array(ruleReferenceSchema).optional(),
    detection: ruleDetectionSchema.optional(),
  })
  .strict();

/**
 * Represents the metadata block for a rule document.
 */
export type RuleMetadata = z.infer<typeof ruleMetadataSchema>;

/**
 * Describes path filters for rule scope.
 */
export const ruleScopePathsSchema = z
  .object({
    include: z.array(nonEmptyStringSchema).optional(),
    exclude: z.array(nonEmptyStringSchema).optional(),
  })
  .strict();

/**
 * Represents path filters for rule scope.
 */
export type RuleScopePaths = z.infer<typeof ruleScopePathsSchema>;

/**
 * Describes the scope block for a rule document.
 */
export const ruleScopeSchema = z
  .object({
    languages: z.array(ruleLanguageSchema),
    paths: ruleScopePathsSchema.optional(),
    changedLinesOnly: z.boolean().optional(),
  })
  .strict();

/**
 * Represents the scope block for a rule document.
 */
export type RuleScope = z.infer<typeof ruleScopeSchema>;

/**
 * Describes a comparison clause attached to a structural predicate.
 */
export const ruleWhereClauseSchema = z.union([
  z
    .object({
      path: nonEmptyStringSchema,
      equals: z.union([nonEmptyStringSchema, z.boolean()]),
    })
    .strict(),
  z
    .object({
      path: nonEmptyStringSchema,
      in: z.array(nonEmptyStringSchema).min(1),
    })
    .strict(),
  z
    .object({
      path: nonEmptyStringSchema,
      matches: nonEmptyStringSchema,
    })
    .strict(),
  z
    .object({
      path: nonEmptyStringSchema,
      exists: z.boolean(),
    })
    .strict(),
]);

/**
 * Represents a comparison clause attached to a structural predicate.
 */
export type RuleWhereClause = z.infer<typeof ruleWhereClauseSchema>;

/**
 * Describes a structural predicate in the match grammar.
 */
export const ruleStructuralPredicateSchema = z
  .object({
    kind: nonEmptyStringSchema,
    bind: nonEmptyStringSchema.optional(),
    where: z.array(ruleWhereClauseSchema).optional(),
  })
  .strict();

/**
 * Represents a structural predicate in the match grammar.
 */
export type RuleStructuralPredicate = z.infer<
  typeof ruleStructuralPredicateSchema
>;

type RuleCondition =
  | { all: RuleCondition[] }
  | { any: RuleCondition[] }
  | { not: RuleCondition }
  | { node: RuleStructuralPredicate }
  | { ancestor: RuleStructuralPredicate }
  | { fact: RuleStructuralPredicate };

/**
 * The public match grammar for a rule document.
 */
export const ruleConditionSchema = z.lazy(() =>
  z.union([
    z
      .object({
        all: z.array(ruleConditionSchema),
      })
      .strict(),
    z
      .object({
        any: z.array(ruleConditionSchema),
      })
      .strict(),
    z
      .object({
        not: ruleConditionSchema,
      })
      .strict(),
    z
      .object({
        node: ruleStructuralPredicateSchema,
      })
      .strict(),
    z
      .object({
        ancestor: ruleStructuralPredicateSchema,
      })
      .strict(),
    z
      .object({
        fact: ruleStructuralPredicateSchema,
      })
      .strict(),
  ]),
) as z.ZodType<RuleCondition>;

/**
 * Represents a single match condition in the public DSL.
 */
export type RuleConditionNode = z.infer<typeof ruleConditionSchema>;

/**
 * Describes the finding payload emitted by a rule.
 */
export const ruleEmitFindingSchema = z
  .object({
    category: findingCategorySchema,
    severity: findingSeveritySchema,
    confidence: findingConfidenceSchema,
    tags: z.array(nonEmptyStringSchema).optional(),
  })
  .strict();

/**
 * Represents the finding payload emitted by a rule.
 */
export interface RuleEmitFinding extends z.infer<typeof ruleEmitFindingSchema> {
  category: FindingCategory;
  severity: FindingSeverity;
  confidence: FindingConfidence;
}

/**
 * Describes the message payload emitted by a rule.
 */
export const ruleEmitMessageSchema = z
  .object({
    title: nonEmptyStringSchema,
    summary: nonEmptyStringSchema,
    detail: nonEmptyStringSchema.optional(),
  })
  .strict();

/**
 * Represents the message payload emitted by a rule.
 */
export type RuleEmitMessage = z.infer<typeof ruleEmitMessageSchema>;

/**
 * Describes the remediation payload emitted by a rule.
 */
export const ruleEmitRemediationSchema = z
  .object({
    summary: nonEmptyStringSchema,
  })
  .strict();

/**
 * Represents the remediation payload emitted by a rule.
 */
export type RuleEmitRemediation = z.infer<typeof ruleEmitRemediationSchema>;

/**
 * Describes the emit block for a rule document.
 */
export const ruleEmitSchema = z
  .object({
    finding: ruleEmitFindingSchema,
    message: ruleEmitMessageSchema,
    remediation: ruleEmitRemediationSchema.optional(),
  })
  .strict();

/**
 * Represents the emit block for a rule document.
 */
export type RuleEmit = z.infer<typeof ruleEmitSchema>;

/**
 * The canonical Zod schema for the public v0 alpha rule document contract.
 */
export const ruleDocumentV0Alpha1Schema = z
  .object({
    apiVersion: z.literal(ruleDocumentApiVersion),
    kind: z.literal(ruleDocumentKind),
    metadata: ruleMetadataSchema,
    vulnerability: ruleVulnerabilitySchema.optional(),
    scope: ruleScopeSchema,
    match: ruleConditionSchema,
    emit: ruleEmitSchema,
  })
  .strict();

/**
 * The canonical TypeScript type for the public v0 alpha rule document contract.
 */
export type RuleDocumentV0Alpha1 = z.infer<typeof ruleDocumentV0Alpha1Schema>;
