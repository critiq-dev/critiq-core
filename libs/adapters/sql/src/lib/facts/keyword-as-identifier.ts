import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const SQL_KEYWORDS = new Set([
  'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'IS', 'NULL',
  'AS', 'ON', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS', 'FULL',
  'USING', 'ORDER', 'BY', 'GROUP', 'HAVING', 'LIMIT', 'OFFSET',
  'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE',
  'CREATE', 'TABLE', 'ALTER', 'DROP', 'INDEX', 'VIEW',
  'DISTINCT', 'ALL', 'UNION', 'EXCEPT', 'INTERSECT',
  'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
  'EXISTS', 'BETWEEN', 'LIKE', 'ILIKE',
  'ASC', 'DESC', 'WITH', 'RECURSIVE',
  'TRUE', 'FALSE', 'PRIMARY', 'KEY', 'FOREIGN', 'REFERENCES',
  'COUNT', 'SUM', 'AVG', 'MIN', 'MAX',
  'CAST', 'COALESCE', 'NULLIF',
]);

function isSqlKeyword(word: string): boolean {
  return SQL_KEYWORDS.has(word.toUpperCase());
}

const FACT_KIND = 'sql.style.keyword-as-identifier';

const ALIAS_PATTERN = /(?:FROM|JOIN)\s+(?:\w+\.)?(\w+)\s+(?:AS\s+)?(\w+)(?=\s*(?:ON|JOIN|INNER|LEFT|RIGHT|OUTER|CROSS|FULL|WHERE|AND|OR|USING|,|\()|\s*$)/gi;

const JOIN_KEYWORDS = new Set([
  'ON', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS', 'FULL',
  'WHERE', 'AND', 'OR', 'USING',
]);

export function collectKeywordAsIdentifierFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const facts: ObservedFact[] = [];
  const regex = new RegExp(ALIAS_PATTERN.source, 'gi');
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    if (isInCommentRange(match.index, commentRanges)) {
      continue;
    }

    const table = match[1];
    const alias = (match[2] || '').trim();

    if (!alias || alias.length === 0 || JOIN_KEYWORDS.has(alias.toUpperCase())) {
      continue;
    }

    if (isSqlKeyword(alias)) {
      const matchLine = text.slice(0, match.index).split('\n').length;
      const matchLineStart = text.lastIndexOf('\n', match.index) + 1;
      const matchColumn = match.index - matchLineStart + 1;

      facts.push({
        id: `sql-detector:${FACT_KIND}:${matchLine}:${matchColumn}:${matchLine}:${matchColumn + alias.length}`,
        kind: FACT_KIND,
        appliesTo: 'block',
        range: {
          startLine: matchLine,
          startColumn: matchColumn,
          endLine: matchLine,
          endColumn: matchColumn + alias.length,
        },
        text: text.slice(match.index, match.index + 60),
        props: {
          alias,
          keyword: alias.toUpperCase(),
          table,
          snippet: text.slice(match.index, match.index + 80),
        },
      });
    }
  }

  return facts;
}
