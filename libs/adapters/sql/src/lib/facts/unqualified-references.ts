import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.style.unqualified-references';

const TABLE_SOURCE_PATTERN = /(?:FROM|JOIN)\s+(?:\w+\.)?(\w+)(?:\s+AS\s+\w+|\s+\w+(?=\s*(?:ON|JOIN|INNER|LEFT|RIGHT|OUTER|CROSS|FULL|WHERE|AND|OR|USING|,|\()|$))?/gi;
const SELECT_COLUMN_PATTERN = /SELECT\s+(.+?)\s+FROM/gi;
const QUALIFIED_REF_PATTERN = /(\w+)\.(\w+)/g;

const SKIP_WORDS = new Set([
  'AND', 'OR', 'NOT', 'IN', 'IS', 'NULL', 'AS', 'ON',
  'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS', 'FULL',
  'JOIN', 'WHERE', 'ORDER', 'BY', 'GROUP', 'HAVING',
  'LIMIT', 'OFFSET', 'DISTINCT', 'ALL', 'UNION',
  'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
  'EXISTS', 'BETWEEN', 'LIKE', 'ILIKE',
  'ASC', 'DESC', 'TRUE', 'FALSE',
  'COUNT', 'SUM', 'AVG', 'MIN', 'MAX',
  'CAST', 'COALESCE', 'NULLIF',
  'SELECT', 'FROM', 'USING',
]);

const FUNCTION_LIKE = /^\w+\(/;
const STRING_LITERAL = /^'[^']*'/;

const IS_QUALIFIED = /^\w+\.\w+/;

function extractBareColumns(selectBody: string): string[] {
  const columns: string[] = [];
  const parts = splitTopLevelCommas(selectBody);

  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed || trimmed === '*') continue;
    if (FUNCTION_LIKE.test(trimmed)) continue;
    if (STRING_LITERAL.test(trimmed)) continue;
    if (/^\d+/.test(trimmed)) continue;
    if (SKIP_WORDS.has(trimmed.toUpperCase())) continue;
    if (IS_QUALIFIED.test(trimmed)) continue;

    const bare = trimmed.split(/\s+/)[0];
    if (bare && !SKIP_WORDS.has(bare.toUpperCase()) && !FUNCTION_LIKE.test(bare) && !STRING_LITERAL.test(bare) && !/^\d+/.test(bare) && bare !== '*') {
      columns.push(bare);
    }
  }

  return columns;
}

function splitTopLevelCommas(text: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';

  for (const char of text) {
    if (char === '(') depth++;
    else if (char === ')') depth--;
    else if (char === ',' && depth === 0) {
      parts.push(current);
      current = '';
      continue;
    }
    current += char;
  }

  if (current.trim()) {
    parts.push(current);
  }

  return parts;
}

function countTableSources(text: string): number {
  const regex = new RegExp(TABLE_SOURCE_PATTERN.source, 'gi');
  const tables = new Set<string>();
  let m: RegExpExecArray | null;

  while ((m = regex.exec(text)) !== null) {
    tables.add(m[1]);
  }

  return tables.size;
}

function countTableSourcesInClause(fromClause: string): number {
  const regex = new RegExp(TABLE_SOURCE_PATTERN.source, 'gi');
  const tables = new Set<string>();
  let m: RegExpExecArray | null;
  let depth = 0;

  for (let i = 0; i < fromClause.length; i++) {
    const ch = fromClause[i];
    if (ch === '(') depth++;
    else if (ch === ')') depth--;
  }

  while ((m = regex.exec(fromClause)) !== null) {
    tables.add(m[1]);
  }

  return tables.size;
}

function findStatementBoundary(text: string, fromPos: number): number {
  let i = fromPos;
  let depth = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '(') depth++;
    else if (ch === ')') { depth--; if (depth < 0) return i; }
    else if (depth === 0 && (ch === ';' || text.slice(i, i + 6).toUpperCase() === 'SELECT')) {
      if (ch === ';') return i;
      const before = text.slice(Math.max(0, i - 10), i).trim();
      if (before.endsWith('(') || before.endsWith(',')) { i++; continue; }
      return i;
    }
    i++;
  }
  return text.length;
}

function extractFromClause(text: string, selectMatchEnd: number): string {
  const fromStart = selectMatchEnd - 4;
  const boundary = findStatementBoundary(text, selectMatchEnd);
  return text.slice(fromStart, boundary);
}

export function collectUnqualifiedReferencesFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const cleanText = text.replace(/'[^']*'/g, '').replace(/"[^"]*"/g, '');

  const facts: ObservedFact[] = [];
  const selectRegex = new RegExp(SELECT_COLUMN_PATTERN.source, 'gi');
  let m: RegExpExecArray | null;

  while ((m = selectRegex.exec(cleanText)) !== null) {
    if (isInCommentRange(m.index, commentRanges)) continue;

    const selectBody = m[1];
    const selectEnd = m.index + m[0].length;
    const fromClause = extractFromClause(cleanText, selectEnd);
    const tableCount = countTableSourcesInClause(fromClause);

    if (tableCount < 2) continue;

    const bareColumns = extractBareColumns(selectBody);

    if (bareColumns.length === 0) continue;

    const selectOffset = m.index;
    const matchLine = text.slice(0, selectOffset).split('\n').length;
    const matchLineStart = text.lastIndexOf('\n', selectOffset) + 1;
    const matchColumn = selectOffset - matchLineStart + 1;

    facts.push({
      id: `sql-detector:${FACT_KIND}:${matchLine}:${matchColumn}:${matchLine}:${matchColumn + 6}`,
      kind: FACT_KIND,
      appliesTo: 'block',
      range: {
        startLine: matchLine,
        startColumn: matchColumn,
        endLine: matchLine,
        endColumn: matchColumn + 6,
      },
      text: text.slice(selectOffset, selectOffset + 60),
      props: {
        unqualifiedColumns: bareColumns.join(', '),
        tableCount,
      },
    });
  }

  return facts;
}
