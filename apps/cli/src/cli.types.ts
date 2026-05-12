import { type Diagnostic } from '@critiq/core-diagnostics';
import { normalizeRuleDocument } from '@critiq/core-ir';
import { formatRuleSpecRunAsJson, runRuleSpec } from '@critiq/testing-harness';
import { type RuleTemplateVariableMap } from '@critiq/core-rules-dsl';

export type OutputFormat = 'pretty' | 'json';
export type PhaseStatus = 'success' | 'failure' | 'skipped';
export type NormalizedRule = ReturnType<typeof normalizeRuleDocument>['rule'];
export type RuleSpecRun = ReturnType<typeof runRuleSpec>;
export type RuleSpecJsonResult = ReturnType<typeof formatRuleSpecRunAsJson>;

export interface CliRuntime {
  cwd?: string;
  writeStdout?: (message: string) => void;
  writeStderr?: (message: string) => void;
  writeRaw?: (message: string) => void;
  isInteractive?: boolean;
}

export interface ParsedArguments {
  positionals: string[];
  format: OutputFormat;
  help: boolean;
  baseRef?: string;
  headRef?: string;
  /** When true, secret scans use staged index content (`git diff --cached`). */
  staged: boolean;
}

export interface CliResultEnvelope {
  command: string;
  format: OutputFormat;
  exitCode: number;
}

export interface ValidateFileResult {
  path: string;
  uri: string;
  success: boolean;
  diagnostics: Diagnostic[];
}

export interface ValidateCommandEnvelope extends CliResultEnvelope {
  target: string;
  matchedFileCount: number;
  results: ValidateFileResult[];
  diagnostics: Diagnostic[];
}

export interface TestSpecResult {
  specPath: string;
  success: boolean;
  diagnostics: Diagnostic[];
  run: RuleSpecRun;
  result: RuleSpecJsonResult;
}

export interface TestCommandEnvelope extends CliResultEnvelope {
  target: string;
  matchedFileCount: number;
  results: TestSpecResult[];
  diagnostics: Diagnostic[];
}

export interface ExplainParsedSummary {
  path: string;
  uri: string;
  ruleId: string | null;
  title: string | null;
  summary: string | null;
  phases: {
    load: PhaseStatus;
    contractValidation: PhaseStatus;
    semanticValidation: PhaseStatus;
    normalization: PhaseStatus;
  };
}

export interface ExplainSemanticStatus {
  success: boolean;
  diagnostics: Diagnostic[];
}

export interface NormalizeCommandEnvelope extends CliResultEnvelope {
  file: {
    path: string;
    uri: string;
  };
  parsedSummary: ExplainParsedSummary;
  semanticStatus: ExplainSemanticStatus;
  normalizedRule: NormalizedRule | null;
  ruleHash: string | null;
  diagnostics: Diagnostic[];
}

export interface ExplainCommandEnvelope extends CliResultEnvelope {
  file: {
    path: string;
    uri: string;
  };
  parsedSummary: ExplainParsedSummary;
  semanticStatus: ExplainSemanticStatus;
  normalizedRule: NormalizedRule | null;
  ruleHash: string | null;
  templateVariables: RuleTemplateVariableMap;
  diagnostics: Diagnostic[];
}

export interface SingleFileCommandState {
  displayPath: string;
  uri: string;
  parsedSummary: ExplainParsedSummary;
  semanticStatus: ExplainSemanticStatus;
  normalizedRule: NormalizedRule | null;
  ruleHash: string | null;
  templateVariables: RuleTemplateVariableMap;
  diagnostics: Diagnostic[];
}
