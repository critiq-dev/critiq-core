import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.style.ambiguous-distinct';

const SELECT_DISTINCT_PATTERN = /SELECT\s+DISTINCT\s+([\s\S]*?)(?:\s+FROM\b|$)/gi;

export function collectAmbiguousDistinctFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const facts: ObservedFact[] = [];
  let match: RegExpExecArray | null;

  while ((match = SELECT_DISTINCT_PATTERN.exec(text)) !== null) {
    if (isInCommentRange(match.index, commentRanges)) {
      continue;
    }

    const selectBody = match[1].trim();
    const columns = splitColumns(selectBody);

    if (columns.length < 3) {
      continue;
    }

    const hasComputedExpression = columns.some((col) => {
      const trimmed = col.trim();
      if (/^\w+$/.test(trimmed)) return false;
      if (/^\w+\.\w+$/.test(trimmed)) return false;
      if (/^\w+\.\*$/.test(trimmed)) return false;
      if (trimmed === '*') return false;
      return true;
    });

    if (!hasComputedExpression) {
      continue;
    }

    const startOffset = match.index;
    const matchLine = text.slice(0, startOffset).split('\n').length;
    const matchLineStart = text.lastIndexOf('\n', startOffset) + 1;
    const matchColumn = startOffset - matchLineStart + 1;
    const matchLen = match[0].length;
    const endColumn = matchColumn + matchLen;

    facts.push({
      id: `sql-detector:${FACT_KIND}:${matchLine}:${matchColumn}:${matchLine}:${endColumn}`,
      kind: FACT_KIND,
      appliesTo: 'block',
      range: {
        startLine: matchLine,
        startColumn: matchColumn,
        endLine: matchLine,
        endColumn,
      },
      text: `SELECT DISTINCT with ${columns.length} columns including computed expressions`,
      props: {
        columnCount: columns.length,
        columnTexts: columns.map((c) => c.trim()),
        hasComputedColumns: hasComputedExpression,
      },
    });
  }

  return facts;
}

function splitColumns(selectBody: string): string[] {
  const columns: string[] = [];
  let depth = 0;
  let current = '';

  for (let i = 0; i < selectBody.length; i++) {
    const ch = selectBody[i];

    if (ch === '(' || ch === '[') {
      depth++;
      current += ch;
    } else if (ch === ')' || ch === ']') {
      depth--;
      current += ch;
    } else if (ch === ',' && depth === 0) {
      columns.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }

  const remaining = current.trim();
  if (remaining.length > 0) {
    columns.push(remaining);
  }

  return columns;
}
