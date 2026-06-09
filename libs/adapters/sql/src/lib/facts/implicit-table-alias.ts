import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.style.implicit-table-alias';

const KEYWORDS = new Set([
  'WHERE', 'ON', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS', 'FULL',
  'GROUP', 'ORDER', 'HAVING', 'LIMIT', 'OFFSET', 'USING', 'AND', 'OR',
  'INTO', 'VALUES', 'SET', 'AS',
  '(', ')', ',',
]);

function isAliasKeyword(word: string): boolean {
  return KEYWORDS.has(word.toUpperCase());
}

export function collectImplicitTableAliasFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const facts: ObservedFact[] = [];

  const tableAliasPattern = /(?:FROM|JOIN)\s+(\w+)\s+(\w+)/gi;
  let match: RegExpExecArray | null;

  while ((match = tableAliasPattern.exec(text)) !== null) {
    if (isInCommentRange(match.index, commentRanges)) {
      continue;
    }

    const _tableName = match[1];
    const potentialAlias = match[2];

    if (isAliasKeyword(potentialAlias)) {
      continue;
    }

    const beforeAlias = text.slice(
      match.index + match[0].indexOf(match[1]) + match[1].length,
      match.index + match[0].length - potentialAlias.length,
    );

    const hasAsKeyword = /\bAS\b/i.test(beforeAlias);

    if (hasAsKeyword) {
      continue;
    }

    const matchLine = text.slice(0, match.index).split('\n').length;
    const matchLineStart = text.lastIndexOf('\n', match.index) + 1;
    const matchColumn = match.index - matchLineStart + 1;

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
      text: match[0],
      props: {
        table: match[1],
        alias: potentialAlias,
      },
    });
  }

  return facts;
}
