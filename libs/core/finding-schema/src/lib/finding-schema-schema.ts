import { z } from 'zod';

const findingSchemaVersion = 'finding/v0' as const;

const nonEmptyStringSchema = z.string().min(1);
const sha256FingerprintSchema = z
  .string()
  .regex(/^sha256:.+$/, 'Expected fingerprint to start with "sha256:".');
const isoDateTimeSchema = z
  .string()
  .datetime({ offset: true, message: 'Expected an ISO 8601 datetime string.' });

/**
 * The version identifier for the canonical v0 finding contract.
 */
export const FINDING_V0_SCHEMA_VERSION = findingSchemaVersion;

/**
 * Enumerates the supported finding categories in schema version v0.
 */
export const findingCategorySchema = z
  .string()
  .regex(
    /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*$/,
    'Expected a dot-delimited category such as "security.injection".',
  );

/**
 * Enumerates the supported finding severities in schema version v0.
 */
export const findingSeveritySchema = z.enum([
  'low',
  'medium',
  'high',
  'critical',
]);

/**
 * Enumerates the supported finding confidence levels in schema version v0.
 */
export const findingConfidenceSchema = z.union([
  z.enum(['low', 'medium', 'high']),
  z.number().min(0).max(1),
]);

/**
 * Identifies the category assigned to a finding.
 */
export type FindingCategory = z.infer<typeof findingCategorySchema>;

/**
 * Identifies the severity assigned to a finding.
 */
export type FindingSeverity = z.infer<typeof findingSeveritySchema>;

/**
 * Identifies the confidence assigned to a finding.
 */
export type FindingConfidence = z.infer<typeof findingConfidenceSchema>;

/**
 * Represents the open attributes bag attached to a finding.
 */
export type FindingAttributes = Record<string, unknown>;

/**
 * Describes an inclusive source range within a file.
 */
export const sourceRangeSchema = z
  .object({
    startLine: z.number().int().positive(),
    startColumn: z.number().int().positive(),
    endLine: z.number().int().positive(),
    endColumn: z.number().int().positive(),
  })
  .strict();

/**
 * Represents a source range within a file.
 */
export type SourceRange = z.infer<typeof sourceRangeSchema>;

/**
 * Describes a finding location bound to a specific file path.
 */
export const findingLocationSchema = z
  .object({
    path: nonEmptyStringSchema,
    startLine: z.number().int().positive(),
    startColumn: z.number().int().positive(),
    endLine: z.number().int().positive(),
    endColumn: z.number().int().positive(),
  })
  .strict();

/**
 * Represents a location attached to a finding.
 */
export type FindingLocation = z.infer<typeof findingLocationSchema>;

/**
 * Describes an evidence item attached to a finding.
 */
export const findingEvidenceSchema = z
  .object({
    kind: nonEmptyStringSchema,
    label: nonEmptyStringSchema,
    path: nonEmptyStringSchema,
    excerpt: nonEmptyStringSchema,
    range: sourceRangeSchema,
  })
  .strict();

/**
 * Represents a single evidence item attached to a finding.
 */
export type FindingEvidence = z.infer<typeof findingEvidenceSchema>;

/**
 * Describes the rule metadata embedded in a finding.
 */
export const findingRuleSchema = z
  .object({
    id: nonEmptyStringSchema,
    name: nonEmptyStringSchema.optional(),
    version: nonEmptyStringSchema.optional(),
  })
  .strict();

/**
 * Represents the rule metadata embedded in a finding.
 */
export type FindingRule = z.infer<typeof findingRuleSchema>;

/**
 * Describes the location block attached to a finding.
 */
export const findingLocationsSchema = z
  .object({
    primary: findingLocationSchema,
    related: z.array(findingLocationSchema).optional(),
  })
  .strict();

/**
 * Represents the locations attached to a finding.
 */
export type FindingLocations = z.infer<typeof findingLocationsSchema>;

/**
 * Describes remediation guidance attached to a finding.
 */
export const findingRemediationSchema = z
  .object({
    summary: nonEmptyStringSchema,
  })
  .strict();

/**
 * Represents remediation guidance attached to a finding.
 */
export type FindingRemediation = z.infer<typeof findingRemediationSchema>;

/**
 * Describes the fingerprint block attached to a finding.
 */
export const findingFingerprintsSchema = z
  .object({
    primary: sha256FingerprintSchema,
    logical: sha256FingerprintSchema.optional(),
  })
  .strict();

/**
 * Represents the fingerprint block attached to a finding.
 */
export type FindingFingerprints = z.infer<typeof findingFingerprintsSchema>;

/**
 * Describes the provenance block attached to a finding.
 */
export const findingProvenanceSchema = z
  .object({
    engineKind: nonEmptyStringSchema,
    engineVersion: nonEmptyStringSchema,
    rulePack: nonEmptyStringSchema.optional(),
    generatedAt: isoDateTimeSchema,
  })
  .strict();

/**
 * Represents the provenance block attached to a finding.
 */
export type FindingProvenance = z.infer<typeof findingProvenanceSchema>;

/**
 * The canonical Zod schema for the v0 finding contract.
 */
export const findingV0Schema = z
  .object({
    schemaVersion: z.literal(findingSchemaVersion),
    findingId: z.string().uuid(),
    rule: findingRuleSchema,
    title: nonEmptyStringSchema,
    summary: nonEmptyStringSchema,
    category: findingCategorySchema,
    severity: findingSeveritySchema,
    confidence: findingConfidenceSchema,
    tags: z.array(nonEmptyStringSchema).optional(),
    locations: findingLocationsSchema,
    evidence: z.array(findingEvidenceSchema).min(1),
    remediation: findingRemediationSchema.optional(),
    fingerprints: findingFingerprintsSchema,
    provenance: findingProvenanceSchema,
    attributes: z.record(z.unknown()).optional(),
  })
  .strict();

/**
 * The canonical TypeScript type for the v0 finding contract.
 */
export type FindingV0 = z.infer<typeof findingV0Schema>;
