import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ZodIssue, ZodIssueCode } from 'zod';

import {
  ruleDocumentV0Alpha1Schema,
  type RuleDocumentV0Alpha1,
} from './rules-dsl-schema';

/**
 * Represents a single validation issue returned by the rule DSL package.
 */
export interface RuleDocumentValidationIssue {
  path: string;
  code: string;
  message: string;
  expected?: string;
  received?: string;
}

/**
 * Represents a successful rule document validation result.
 */
export interface RuleDocumentValidationSuccess {
  success: true;
  data: RuleDocumentV0Alpha1;
}

/**
 * Represents a failed rule document validation result.
 */
export interface RuleDocumentValidationFailure {
  success: false;
  issues: RuleDocumentValidationIssue[];
}

/**
 * Represents the validation result returned by validateRuleDocument().
 */
export type RuleDocumentValidationResult =
  | RuleDocumentValidationSuccess
  | RuleDocumentValidationFailure;

/**
 * The checked-in JSON Schema artifact for RuleDocumentV0Alpha1.
 */
function loadRuleDocumentV0Alpha1JsonSchema(): Record<string, unknown> {
  const candidatePaths = [
    resolve(__dirname, './schema/rule-document-v0alpha1.schema.json'),
    resolve(__dirname, '../../schema/rule-document-v0alpha1.schema.json'),
    resolve(
      __dirname,
      '../../../../../workspace_modules/@critiq/core-rules-dsl/schema/rule-document-v0alpha1.schema.json',
    ),
  ];

  for (const candidatePath of candidatePaths) {
    if (existsSync(candidatePath)) {
      return JSON.parse(readFileSync(candidatePath, 'utf8')) as Record<
        string,
        unknown
      >;
    }
  }

  throw new Error('Unable to locate rule-document-v0alpha1.schema.json.');
}

export const ruleDocumentV0Alpha1JsonSchema =
  loadRuleDocumentV0Alpha1JsonSchema();

function toIssuePath(path: (string | number)[]): string {
  if (path.length === 0) {
    return '/';
  }

  return `/${path.map((segment) => String(segment)).join('/')}`;
}

function normalizeZodIssue(issue: ZodIssue): RuleDocumentValidationIssue {
  const normalized: RuleDocumentValidationIssue = {
    path: toIssuePath(issue.path),
    code: issue.code,
    message: issue.message,
  };

  if (issue.code === ZodIssueCode.invalid_type) {
    normalized.expected = issue.expected;
    normalized.received = issue.received;
  }

  if (issue.code === ZodIssueCode.invalid_enum_value) {
    normalized.expected = issue.options.join('|');
    normalized.received = String(issue.received);
  }

  if (issue.code === ZodIssueCode.unrecognized_keys) {
    normalized.expected = 'No unknown keys';
    normalized.received = issue.keys.join('|');
  }

  if (
    issue.code === ZodIssueCode.invalid_string &&
    issue.validation !== 'regex' &&
    typeof issue.validation === 'string'
  ) {
    normalized.expected = issue.validation;
  }

  return normalized;
}

/**
 * Validates unknown input against the public RuleDocumentV0Alpha1 contract.
 */
export function validateRuleDocument(
  input: unknown,
): RuleDocumentValidationResult {
  const result = ruleDocumentV0Alpha1Schema.safeParse(input);

  if (result.success) {
    return {
      success: true,
      data: result.data,
    };
  }

  return {
    success: false,
    issues: result.error.issues.map(normalizeZodIssue),
  };
}

/**
 * Throws if the provided value does not satisfy the RuleDocumentV0Alpha1 contract.
 */
export function assertValidRuleDocument(
  input: unknown,
): asserts input is RuleDocumentV0Alpha1 {
  const result = validateRuleDocument(input);

  if (!result.success) {
    const failure = result as RuleDocumentValidationFailure;
    const error = new Error('Rule document validation failed.');

    Object.assign(error, {
      issues: failure.issues,
    });

    throw error;
  }
}

/**
 * Returns true when the provided value satisfies the RuleDocumentV0Alpha1 contract.
 */
export function isRuleDocument(input: unknown): input is RuleDocumentV0Alpha1 {
  return ruleDocumentV0Alpha1Schema.safeParse(input).success;
}
