import type { ContractValidatedRuleDocument } from './rules-dsl-semantic';
import type { RuleDetection, RuleReference } from './rules-dsl-schema';
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
  rationale?: string;
  references: RuleReference[];
  detection?: RuleDetection;
  hasVulnerabilityBlock: boolean;
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
    rationale: document.metadata.rationale,
    references: document.metadata.references ?? [],
    detection: document.metadata.detection,
    hasVulnerabilityBlock: document.vulnerability !== undefined,
    templateVariables: inferRuleTemplateVariables(document),
  };
}
