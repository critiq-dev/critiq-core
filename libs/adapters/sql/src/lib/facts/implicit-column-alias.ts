import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.style.implicit-column-alias';

const KEYWORDS = new Set([
  'FROM', 'WHERE', 'ON', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS',
  'GROUP', 'ORDER', 'HAVING', 'LIMIT', 'OFFSET', 'USING', 'AND', 'OR',
  'INTO', 'VALUES', 'SET',
  ',',
]);

function isAliasKeyword(word: string): boolean {
  return KEYWORDS.has(word.toUpperCase());
}

export function collectImplicitColumnAliasFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const facts: ObservedFact[] = [];
  const selectPattern = /SELECT\s+([\s\S]*?)(?:\s+FROM\b|$)/gi;
  let selectMatch: RegExpExecArray | null;

  while ((selectMatch = selectPattern.exec(text)) !== null) {
    if (isInCommentRange(selectMatch.index, commentRanges)) {
      continue;
    }

    const selectBody = selectMatch[1];
    const columns = splitColumns(selectBody);

    for (const col of columns) {
      const trimmed = col.trim();
      const parts = trimmed.split(/\s+/);

      if (parts.length < 2) {
        continue;
      }

      if (parts[0]!.toUpperCase() === 'DISTINCT') {
        continue;
      }

      const expressionParts = [];
      let aliasIndex = -1;

      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        if (!isAliasKeyword(part) && i > 0 && i === parts.length - 1) {
          aliasIndex = i;
          break;
        }
        expressionParts.push(part);
      }

      if (aliasIndex < 1) {
        continue;
      }

      const lastExprPart = expressionParts[expressionParts.length - 1] ?? '';

      if (lastExprPart.endsWith(')') || lastExprPart.endsWith('"') || lastExprPart.endsWith("'")) {
        continue;
      }

      if (/\bAS\b/i.test(col)) {
        continue;
      }

      const expr = expressionParts.join(' ');
      const alias = parts[aliasIndex];

      const colStartOffset = selectMatch.index + selectMatch[0].indexOf(trimmed);
      const matchLine = text.slice(0, colStartOffset).split('\n').length;
      const matchLineStart = text.lastIndexOf('\n', colStartOffset) + 1;
      const matchColumn = colStartOffset - matchLineStart + 1;

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
        text: `${expr} ${alias}`,
        props: { expression: expr, alias },
      });
    }
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
