import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ZodIssue, ZodIssueCode } from 'zod';

import { findingV0Schema, type FindingV0 } from './finding-schema-schema';

/**
 * Represents a single validation issue returned by the finding schema package.
 */
export interface FindingValidationIssue {
  path: string;
  code: string;
  message: string;
  expected?: string;
  received?: string;
}

/**
 * Represents a successful validation result.
 */
export interface FindingValidationSuccess {
  success: true;
  data: FindingV0;
}

/**
 * Represents a failed validation result.
 */
export interface FindingValidationFailure {
  success: false;
  issues: FindingValidationIssue[];
}

/**
 * Represents the validation result returned by validateFinding().
 */
export type FindingValidationResult =
  | FindingValidationSuccess
  | FindingValidationFailure;

/**
 * The checked-in JSON Schema artifact for FindingV0.
 */
function loadFindingV0JsonSchema(): Record<string, unknown> {
  const candidatePaths = [
    resolve(__dirname, './schema/finding-v0.schema.json'),
    resolve(__dirname, '../../schema/finding-v0.schema.json'),
    resolve(
      __dirname,
      '../../../../../workspace_modules/@critiq/core-finding-schema/schema/finding-v0.schema.json',
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

  throw new Error('Unable to locate finding-v0.schema.json.');
}

export const findingV0JsonSchema = loadFindingV0JsonSchema();

function toIssuePath(path: (string | number)[]): string {
  if (path.length === 0) {
    return '/';
  }

  return `/${path.map((segment) => String(segment)).join('/')}`;
}

function normalizeZodIssue(issue: ZodIssue): FindingValidationIssue {
  const normalized: FindingValidationIssue = {
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
 * Validates unknown input against the canonical FindingV0 contract.
 */
export function validateFinding(input: unknown): FindingValidationResult {
  const result = findingV0Schema.safeParse(input);

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
 * Throws if the provided value does not satisfy the FindingV0 contract.
 */
export function assertValidFinding(input: unknown): asserts input is FindingV0 {
  const result = validateFinding(input);

  if (!result.success) {
    const failure = result as FindingValidationFailure;
    const error = new Error('Finding validation failed.');

    Object.assign(error, {
      issues: failure.issues,
    });

    throw error;
  }
}

/**
 * Returns true when the provided value satisfies the FindingV0 contract.
 */
export function isFinding(input: unknown): input is FindingV0 {
  return findingV0Schema.safeParse(input).success;
}
