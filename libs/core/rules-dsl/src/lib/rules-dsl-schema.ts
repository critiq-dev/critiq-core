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
    scope: ruleScopeSchema,
    match: ruleConditionSchema,
    emit: ruleEmitSchema,
  })
  .strict();

/**
 * The canonical TypeScript type for the public v0 alpha rule document contract.
 */
export type RuleDocumentV0Alpha1 = z.infer<typeof ruleDocumentV0Alpha1Schema>;
