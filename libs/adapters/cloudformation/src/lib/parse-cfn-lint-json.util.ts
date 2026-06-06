import type { CfnLintJsonMatch } from './cfn-lint.types';

export interface ParsedCfnLintFinding {
  ruleId: string;
  level: string;
  message: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
}

function isCfnLintJsonMatch(value: unknown): value is CfnLintJsonMatch {
  return typeof value === 'object' && value !== null;
}

/**
 * Parses cfn-lint JSON output into normalized finding records.
 */
export function parseCfnLintJson(stdout: string): ParsedCfnLintFinding[] {
  const trimmed = stdout.trim();

  if (!trimmed) {
    return [];
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(trimmed) as unknown;
  } catch {
    return [];
  }

  if (!Array.isArray(parsed)) {
    return [];
  }

  const findings: ParsedCfnLintFinding[] = [];

  for (const entry of parsed) {
    if (!isCfnLintJsonMatch(entry)) {
      continue;
    }

    const ruleId = entry.Rule?.Id?.trim();

    if (!ruleId) {
      continue;
    }

    const line = entry.Location?.Start?.LineNumber ?? 1;
    const column = entry.Location?.Start?.ColumnNumber ?? 1;
    const endLine = entry.Location?.End?.LineNumber ?? line;
    const endColumn = entry.Location?.End?.ColumnNumber ?? column;
    const message = entry.Message?.trim() ?? '';
    const level = entry.Level?.trim() ?? 'Unknown';

    findings.push({
      ruleId,
      level,
      message,
      line,
      column,
      endLine,
      endColumn,
    });
  }

  return findings;
}
