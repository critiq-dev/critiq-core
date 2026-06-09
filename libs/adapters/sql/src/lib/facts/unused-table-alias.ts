import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.style.unused-table-alias';

const TABLE_ALIAS_DEF_PATTERN = /(?:FROM|JOIN)\s+(?:\w+\.)?(\w+)(?:\s+AS\s+(\w+)|\s+(\w+)(?=\s*(?:ON|JOIN|INNER|LEFT|RIGHT|OUTER|CROSS|WHERE|AND|OR|USING|,|\()|$))/gi;

const KEYWORDS = new Set([
  'ON', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS', 'FULL',
  'WHERE', 'AND', 'OR', 'USING',
]);

interface AliasDef {
  alias: string;
  table: string;
  offset: number;
}

export function collectUnusedTableAliasFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const aliasDefs: AliasDef[] = [];
  const regex = new RegExp(TABLE_ALIAS_DEF_PATTERN.source, 'gi');
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    if (isInCommentRange(match.index, commentRanges)) {
      continue;
    }

    const table = match[1];
    const alias = (match[2] || match[3] || '').trim();

    if (!alias || alias.length === 0 || KEYWORDS.has(alias.toUpperCase())) {
      continue;
    }

    aliasDefs.push({ alias, table, offset: match.index });
  }

  const facts: ObservedFact[] = [];

  for (const def of aliasDefs) {
    const aliasRefPattern = new RegExp(`\\b${escapeRegex(def.alias)}\\.`, 'gi');
    const refRegex = new RegExp(aliasRefPattern.source, 'gi');
    let refMatch: RegExpExecArray | null;
    let isUsed = false;

    while ((refMatch = refRegex.exec(text)) !== null) {
      if (isInCommentRange(refMatch.index, commentRanges)) {
        continue;
      }

      if (refMatch.index !== def.offset) {
        isUsed = true;
        break;
      }
    }

    if (!isUsed) {
      const matchLine = text.slice(0, def.offset).split('\n').length;
      const matchLineStart = text.lastIndexOf('\n', def.offset) + 1;
      const matchColumn = def.offset - matchLineStart + 1;

      facts.push({
        id: `sql-detector:${FACT_KIND}:${matchLine}:${matchColumn}:${matchLine}:${matchColumn + def.alias.length}`,
        kind: FACT_KIND,
        appliesTo: 'file',
        range: {
          startLine: matchLine,
          startColumn: matchColumn,
          endLine: matchLine,
          endColumn: matchColumn + def.alias.length,
        },
        text: text.slice(def.offset, def.offset + 60),
        props: {
          alias: def.alias,
          table: def.table,
        },
      });
    }
  }

  return facts;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
