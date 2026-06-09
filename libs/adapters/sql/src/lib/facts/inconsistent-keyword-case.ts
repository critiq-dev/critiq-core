import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.style.inconsistent-keyword-case';

const SQL_KEYWORDS = [
  'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'IS', 'NULL',
  'AS', 'ON', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS', 'FULL',
  'USING', 'ORDER', 'BY', 'GROUP', 'HAVING', 'LIMIT', 'OFFSET',
  'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE',
  'CREATE', 'TABLE', 'ALTER', 'DROP', 'INDEX', 'VIEW',
  'DISTINCT', 'ALL', 'UNION', 'EXCEPT', 'INTERSECT',
  'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
  'EXISTS', 'BETWEEN', 'LIKE',
  'ASC', 'DESC', 'WITH', 'RECURSIVE',
  'TRUE', 'FALSE',
  'COUNT', 'SUM', 'AVG', 'MIN', 'MAX',
  'CAST', 'COALESCE', 'NULLIF',
];

const KEYWORD_PATTERN = new RegExp(
  `\\b(${SQL_KEYWORDS.join('|')})\\b`,
  'gi',
);

function classifyCase(word: string): 'upper' | 'lower' | 'mixed' {
  if (word === word.toUpperCase()) return 'upper';
  if (word === word.toLowerCase()) return 'lower';
  return 'mixed';
}

export function collectInconsistentKeywordCaseFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const casesPerKeyword = new Map<string, Set<'upper' | 'lower' | 'mixed'>>();
  let hasUpperKeyword = false;
  let hasLowerKeyword = false;

  let match: RegExpExecArray | null;
  const regex = new RegExp(KEYWORD_PATTERN.source, 'gi');

  while ((match = regex.exec(text)) !== null) {
    if (isInCommentRange(match.index, commentRanges)) {
      continue;
    }

    const keyword = match[1];
    const nextChar = text[match.index + keyword.length];
    if (nextChar === '.') continue;

    const before = text.slice(Math.max(0, match.index - 20), match.index).trim().split(/\s+/).pop()?.toUpperCase();
    if (before === 'AS') continue;

    const upperKeyword = keyword.toUpperCase();
    const kind = classifyCase(keyword);

    if (kind === 'upper') hasUpperKeyword = true;
    if (kind === 'lower') hasLowerKeyword = true;

    const existing = casesPerKeyword.get(upperKeyword);
    if (existing) {
      existing.add(kind);
    } else {
      casesPerKeyword.set(upperKeyword, new Set([kind]));
    }
  }

  if (hasUpperKeyword && hasLowerKeyword) {
    const lines = text.split('\n');
    return [
      {
        id: `sql-detector:${FACT_KIND}:1:1:${lines.length}:${lines.length > 0 ? text.length - text.lastIndexOf('\n') : 1}`,
        kind: FACT_KIND,
        appliesTo: 'file',
        range: {
          startLine: 1,
          startColumn: 1,
          endLine: lines.length,
          endColumn: lines.length > 0 ? text.length - text.lastIndexOf('\n') : 1,
        },
        text: text.slice(0, 80),
        props: {
          mixedKeywords: [...casesPerKeyword.entries()]
            .filter(([_, kinds]) => kinds.size > 1)
            .map(([kw]) => kw)
            .sort(),
        },
      },
    ];
  }

  return [];
}
