import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.style.duplicate-table-aliases';

const TABLE_ALIAS_PATTERN = /(?:FROM|JOIN)\s+(?:\w+\.)?(\w+)(?:\s+AS\s+(\w+)|\s+(\w+)(?=\s+(?:ON|JOIN|INNER|LEFT|RIGHT|OUTER|CROSS|WHERE|AND|OR|USING|,|\()|$))/gi;

const KEYWORDS = new Set([
  'ON', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS', 'FULL',
  'WHERE', 'AND', 'OR', 'USING',
]);

export function collectDuplicateTableAliasesFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const aliasCount = new Map<string, { count: number; refs: { alias: string; offset: number }[] }>();

  const regex = new RegExp(TABLE_ALIAS_PATTERN.source, 'gi');
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    if (isInCommentRange(match.index, commentRanges)) {
      continue;
    }

    const alias = (match[2] || match[3] || '').trim();

    if (alias.length === 0 || KEYWORDS.has(alias.toUpperCase())) {
      continue;
    }

    const existing = aliasCount.get(alias);

    if (existing) {
      existing.count++;
      existing.refs.push({ alias, offset: match.index });
    } else {
      aliasCount.set(alias, {
        count: 1,
        refs: [{ alias, offset: match.index }],
      });
    }
  }

  const facts: ObservedFact[] = [];

  for (const [alias, info] of aliasCount) {
    if (info.count < 2) {
      continue;
    }

    const firstRef = info.refs[0]!;
    const matchLine = text.slice(0, firstRef.offset).split('\n').length;
    const matchLineStart = text.lastIndexOf('\n', firstRef.offset) + 1;
    const matchColumn = firstRef.offset - matchLineStart + 1;

    facts.push({
      id: `sql-detector:${FACT_KIND}:${matchLine}:${matchColumn}:${matchLine}:${matchColumn + alias.length}`,
      kind: FACT_KIND,
      appliesTo: 'file',
      range: {
        startLine: matchLine,
        startColumn: matchColumn,
        endLine: matchLine,
        endColumn: matchColumn + alias.length,
      },
      text: `Duplicate alias: ${alias}`,
      props: {
        alias,
        occurrences: info.count,
        offsets: info.refs.map((r) => r.offset),
      },
    });
  }

  return facts;
}
