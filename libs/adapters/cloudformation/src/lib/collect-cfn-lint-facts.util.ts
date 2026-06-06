import type { ObservedFact } from '@critiq/core-rules-engine';

import type { ParsedCfnLintFinding } from './parse-cfn-lint-json.util';

export const CFN_LINT_FACT_KIND = 'cfn.lint.finding' as const;
export const CFN_LINT_DETECTOR = 'cfn-lint' as const;

function lineColumnToOffset(
  text: string,
  line: number,
  column: number,
): number {
  const lines = text.split('\n');
  const safeLine = Math.max(line, 1);
  let offset = 0;

  for (let index = 0; index < safeLine - 1 && index < lines.length; index += 1) {
    offset += lines[index].length + 1;
  }

  const lineText = lines[safeLine - 1] ?? '';
  offset += Math.min(Math.max(column - 1, 0), lineText.length);

  return offset;
}

function createRangeFromLineColumns(
  text: string,
  startLine: number,
  startColumn: number,
  endLine: number,
  endColumn: number,
) {
  const startOffset = lineColumnToOffset(text, startLine, startColumn);
  const endOffset = Math.max(
    startOffset + 1,
    lineColumnToOffset(text, endLine, endColumn),
  );
  const lines = text.split('\n');
  const excerptLines = lines.slice(
    Math.max(startLine - 1, 0),
    Math.min(endLine, lines.length),
  );

  return {
    startOffset,
    endOffset,
    excerpt: excerptLines.join('\n'),
    range: {
      startLine,
      startColumn,
      endLine,
      endColumn,
    },
  };
}

/**
 * Converts parsed cfn-lint findings into Critiq observed facts.
 */
export function collectCfnLintFacts(
  text: string,
  findings: readonly ParsedCfnLintFinding[],
): ObservedFact[] {
  return findings.map((finding) => {
    const positioned = createRangeFromLineColumns(
      text,
      finding.line,
      finding.column,
      finding.endLine,
      finding.endColumn,
    );

    return {
      id: [
        CFN_LINT_DETECTOR,
        CFN_LINT_FACT_KIND,
        finding.ruleId,
        positioned.range.startLine,
        positioned.range.startColumn,
        positioned.range.endLine,
        positioned.range.endColumn,
      ].join(':'),
      kind: CFN_LINT_FACT_KIND,
      appliesTo: 'file',
      range: positioned.range,
      text: positioned.excerpt,
      props: {
        ruleId: finding.ruleId,
        level: finding.level,
        message: finding.message,
        line: finding.line,
        column: finding.column,
      },
    };
  });
}
