import type { ContractValidatedRuleDocument } from './rules-dsl-semantic';
import {
  inferRuleTemplateVariables,
  type RuleTemplateVariableMap,
} from './rules-dsl-template-variables';

/**
 * Represents explain-oriented summary fields derived from a validated rule.
 */
export interface RuleExplainSummary {
  uri: string;
  ruleId: string;
  title: string;
  summary: string;
  templateVariables: RuleTemplateVariableMap;
}

/**
 * Builds reusable explain output from a contract-valid rule document.
 */
export function summarizeValidatedRuleDocument(
  validatedRuleDocument: ContractValidatedRuleDocument,
): RuleExplainSummary {
  const { uri, document } = validatedRuleDocument;

  return {
    uri,
    ruleId: document.metadata.id,
    title: document.metadata.title,
    summary: document.metadata.summary,
    templateVariables: inferRuleTemplateVariables(document),
  };
}
