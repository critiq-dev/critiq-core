import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.style.column-expression-without-alias';

const SELECT_BODY_PATTERN = /SELECT\s+([\s\S]*?)(?:\s+FROM\b|$)/gi;

interface ColumnDef {
  text: string;
  offset: number;
}

export function collectColumnExpressionWithoutAliasFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const facts: ObservedFact[] = [];
  const columns = extractColumns(text, commentRanges);

  for (const col of columns) {
    const trimmed = col.text.trim();

    if (trimmed.length === 0) {
      continue;
    }

    if (trimmed.toUpperCase().startsWith('DISTINCT')) {
      continue;
    }

    if (/\bAS\b/i.test(trimmed)) {
      continue;
    }

    if (isSimpleColumnRef(trimmed)) {
      continue;
    }

    if (isStarExpression(trimmed)) {
      continue;
    }

    if (hasAlias(trimmed)) {
      continue;
    }

    const matchLine = text.slice(0, col.offset).split('\n').length;
    const matchLineStart = text.lastIndexOf('\n', col.offset) + 1;
    const matchColumn = col.offset - matchLineStart + 1;

    facts.push({
      id: `sql-detector:${FACT_KIND}:${matchLine}:${matchColumn}:${matchLine}:${matchColumn + trimmed.length}`,
      kind: FACT_KIND,
      appliesTo: 'block',
      range: {
        startLine: matchLine,
        startColumn: matchColumn,
        endLine: matchLine,
        endColumn: matchColumn + trimmed.length,
      },
      text: trimmed,
      props: { expression: trimmed },
    });
  }

  return facts;
}

function extractColumns(sql: string, commentRanges: { startOffset: number; endOffset: number }[]): ColumnDef[] {
  const columns: ColumnDef[] = [];
  let selectMatch: RegExpExecArray | null;
  const selectRegex = new RegExp(SELECT_BODY_PATTERN.source, 'gi');

  while ((selectMatch = selectRegex.exec(sql)) !== null) {
    if (isInCommentRange(selectMatch.index, commentRanges)) {
      continue;
    }

    const selectBody = selectMatch[1];
    const bodyStartOffset = selectMatch.index + 'SELECT'.length;

    const parts = splitSelectColumns(selectBody);

    for (const part of parts) {
      const trimmed = part.text.trim();
      if (trimmed.length === 0) {
        continue;
      }

      const colOffset = bodyStartOffset + part.offset;
      columns.push({ text: trimmed, offset: colOffset });
    }
  }

  return columns;
}

function splitSelectColumns(selectBody: string): { text: string; offset: number }[] {
  const columns: { text: string; offset: number }[] = [];
  let depth = 0;
  let current = '';
  let currentStart = 0;

  for (let i = 0; i < selectBody.length; i++) {
    const ch = selectBody[i];

    if (ch === '(' || ch === '[') {
      if (depth === 0 && current.length === 0) {
        currentStart = i;
      }
      depth++;
      current += ch;
    } else if (ch === ')' || ch === ']') {
      depth--;
      current += ch;
    } else if (ch === ',' && depth === 0) {
      columns.push({ text: current, offset: currentStart });
      current = '';
      currentStart = i + 1;
    } else {
      if (current.length === 0) {
        currentStart = i;
      }
      current += ch;
    }
  }

  if (current.trim().length > 0) {
    columns.push({ text: current, offset: currentStart });
  }

  return columns;
}

function isSimpleColumnRef(expr: string): boolean {
  const trimmed = expr.trim();
  if (/^\w+$/.test(trimmed)) return true;
  if (/^\w+\.\w+$/.test(trimmed)) return true;
  if (/^\w+\.\*$/.test(trimmed)) return true;
  return false;
}

function isStarExpression(expr: string): boolean {
  return expr.trim() === '*';
}

function hasAlias(expr: string): boolean {
  const parts = expr.trim().split(/\s+/);
  if (parts.length < 2) return false;
  if (/\bAS\b/i.test(expr)) return true;

  const lastPart = parts[parts.length - 1]!;
  if (lastPart.endsWith(')') || lastPart.endsWith('"') || lastPart.endsWith("'")) {
    return false;
  }

  if (/^\w+$/i.test(lastPart)) {
    return lastPart.length <= 64;
  }

  return false;
}

function isFunctionLike(expr: string): boolean {
  return /^\w+\s*\(/i.test(expr.trim());
}
