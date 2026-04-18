import type { RuleDocumentV0Alpha1 } from './rules-dsl-schema';

/**
 * Enumerates the user-facing template fields supported in the v0 rule DSL.
 */
export const RULE_TEMPLATE_FIELD_PATHS = [
  'emit.message.title',
  'emit.message.summary',
  'emit.message.detail',
  'emit.remediation.summary',
] as const;

/**
 * Represents a user-facing template field path.
 */
export type RuleTemplateFieldPath = (typeof RULE_TEMPLATE_FIELD_PATHS)[number];

/**
 * Represents one placeholder reference discovered in a rule template.
 */
export interface RuleTemplateVariableReference {
  expression: string;
  raw: string;
  root: string;
  segments: string[];
}

/**
 * Represents the scan result for a single template field.
 */
export interface RuleTemplateFieldScanResult {
  references: RuleTemplateVariableReference[];
  malformed: boolean;
}

/**
 * Represents inferred placeholders grouped by template field.
 */
export type RuleTemplateVariableMap = Record<
  RuleTemplateFieldPath,
  RuleTemplateVariableReference[]
>;

/**
 * Scans a single template field for `${...}` placeholders.
 */
export function scanRuleTemplateField(value: string): RuleTemplateFieldScanResult {
  const references: RuleTemplateVariableReference[] = [];
  const pattern = /\$\{([^}]+)\}/g;
  const placeholderOpenCount = value.split('${').length - 1;

  for (const match of value.matchAll(pattern)) {
    const expression = match[1];

    references.push({
      expression,
      raw: match[0],
      root: expression.split('.')[0] ?? '',
      segments: expression.split('.'),
    });
  }

  return {
    references,
    malformed: placeholderOpenCount !== references.length,
  };
}

/**
 * Infers all placeholder references present in user-facing template fields.
 */
export function inferRuleTemplateVariables(
  document: Pick<RuleDocumentV0Alpha1, 'emit'>,
): RuleTemplateVariableMap {
  return {
    'emit.message.title': scanRuleTemplateField(document.emit.message.title).references,
    'emit.message.summary': scanRuleTemplateField(document.emit.message.summary)
      .references,
    'emit.message.detail': document.emit.message.detail
      ? scanRuleTemplateField(document.emit.message.detail).references
      : [],
    'emit.remediation.summary': document.emit.remediation?.summary
      ? scanRuleTemplateField(document.emit.remediation.summary).references
      : [],
  };
}
