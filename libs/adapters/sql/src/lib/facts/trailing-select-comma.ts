import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.style.trailing-select-comma';

const TRAILING_COMMA_PATTERN = /,\s*\n?\s*FROM\b/gi;

export function collectTrailingSelectCommaFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const facts: ObservedFact[] = [];
  const regex = new RegExp(TRAILING_COMMA_PATTERN.source, 'gi');
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    if (isInCommentRange(match.index, commentRanges)) {
      continue;
    }

    const commaOffset = match.index;
    const fromOffset = match.index + match[0].indexOf('FROM');
    const matchLine = text.slice(0, commaOffset).split('\n').length;
    const matchLineStart = text.lastIndexOf('\n', commaOffset) + 1;
    const matchColumn = commaOffset - matchLineStart + 1;

    facts.push({
      id: `sql-detector:${FACT_KIND}:${matchLine}:${matchColumn}:${matchLine}:${matchColumn + 1}`,
      kind: FACT_KIND,
      appliesTo: 'block',
      range: {
        startLine: matchLine,
        startColumn: matchColumn,
        endLine: matchLine + text.slice(commaOffset, fromOffset).split('\n').length - 1,
        endColumn: fromOffset - text.lastIndexOf('\n', fromOffset),
      },
      text: text.slice(commaOffset, fromOffset + 4).trim(),
      props: {
        snippet: text.slice(Math.max(0, commaOffset - 20), fromOffset + 20).trim(),
        offset: commaOffset,
      },
    });
  }

  return facts;
}
