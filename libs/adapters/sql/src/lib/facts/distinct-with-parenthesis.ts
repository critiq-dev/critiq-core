import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.style.distinct-with-parenthesis';

const DISTINCT_PAREN_PATTERN = /\bDISTINCT\s*\(/gi;

export function collectDistinctWithParenthesisFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const facts: ObservedFact[] = [];

  let match: RegExpExecArray | null;

  while ((match = DISTINCT_PAREN_PATTERN.exec(text)) !== null) {
    if (isInCommentRange(match.index, commentRanges)) {
      continue;
    }

    const startOffset = match.index;
    const endOffset = match.index + match[0].length;

    const matchLine = text.slice(0, startOffset).split('\n').length;
    const matchLineStart = text.lastIndexOf('\n', startOffset) + 1;
    const matchColumn = startOffset - matchLineStart + 1;

    facts.push({
      id: `sql-detector:${FACT_KIND}:${matchLine}:${matchColumn}:${matchLine}:${matchColumn + match[0].length}`,
      kind: FACT_KIND,
      appliesTo: 'block',
      range: {
        startLine: matchLine,
        startColumn: matchColumn,
        endLine: matchLine,
        endColumn: matchColumn + match[0].length,
      },
      text: `DISTINCT(...) usage`,
      props: { snippet: match[0] },
    });
  }

  return facts;
}
