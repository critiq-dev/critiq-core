import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.style.inconsistent-capitalization';

const SQL_KEYWORDS = new Set([
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
  'PRIMARY', 'KEY', 'FOREIGN', 'REFERENCES',
  'AUTO_INCREMENT', 'DEFAULT', 'NOT', 'NULL',
  'INDEX', 'UNIQUE', 'CONSTRAINT',
  'COLUMN', 'ADD', 'DROP', 'MODIFY', 'CHANGE',
  'IF', 'ELSE', 'THEN', 'END',
  'BEGIN', 'COMMIT', 'ROLLBACK',
  'CASCADE', 'RESTRICT', 'NO', 'ACTION',
  'AFTER', 'BEFORE', 'DATABASE', 'SCHEMA',
  'PROCEDURE', 'FUNCTION', 'TRIGGER', 'EVENT',
  'INT', 'INTEGER', 'BIGINT', 'SMALLINT', 'TINYINT',
  'VARCHAR', 'CHAR', 'TEXT', 'BOOLEAN', 'BOOL',
  'DATE', 'DATETIME', 'TIMESTAMP', 'FLOAT', 'DOUBLE', 'DECIMAL',
  'BLOB', 'ENUM',
]);

const REFERENCE_PATTERN = /[A-Za-z_]\w*/g;

export function collectInconsistentCapitalizationFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const casingMap = new Map<string, Set<string>>();

  let match: RegExpExecArray | null;

  while ((match = REFERENCE_PATTERN.exec(text)) !== null) {
    if (isInCommentRange(match.index, commentRanges)) {
      continue;
    }

    const word = match[0];

    if (SQL_KEYWORDS.has(word.toUpperCase())) {
      continue;
    }

    const lower = word.toLowerCase();
    const existing = casingMap.get(lower);

    if (existing) {
      existing.add(word);
    } else {
      casingMap.set(lower, new Set([word]));
    }
  }

  const inconsistent: string[] = [];

  for (const [lower, casings] of casingMap) {
    if (casings.size > 1) {
      inconsistent.push(lower);
    }
  }

  if (inconsistent.length === 0) {
    return [];
  }

  const textLen = text.length;

  return [
    {
      id: `sql-detector:${FACT_KIND}:1:1:${text.split('\n').length}:${textLen - text.lastIndexOf('\n')}`,
      kind: FACT_KIND,
      appliesTo: 'file',
      range: {
        startLine: 1,
        startColumn: 1,
        endLine: text.split('\n').length,
        endColumn: textLen - text.lastIndexOf('\n'),
      },
      text: text.slice(0, 80),
      props: {
        inconsistentIdentifiers: inconsistent.sort(),
        casings: Object.fromEntries(
          [...casingMap.entries()]
            .filter(([lower]) => inconsistent.includes(lower))
            .map(([lower, set]) => [lower, [...set].sort()]),
        ),
      },
    },
  ];
}
