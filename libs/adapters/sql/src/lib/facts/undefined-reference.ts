import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { findSqlCommentRanges, isInCommentRange } from '../sql-comments';

const FACT_KIND = 'sql.correctness.undefined-reference';

const TABLE_PATTERN = /(?:FROM|JOIN)\s+(?:(\w+)\.)?(\w+)(?:\s+AS\s+(\w+)|\s+(\w+)(?=\s*(?:ON|JOIN|INNER|LEFT|RIGHT|OUTER|CROSS|FULL|WHERE|AND|OR|USING|,|\()|$))?/gi;
const QUALIFIED_REF_PATTERN = /(\w+)\.(\w+)/g;
const BARE_TABLE_PATTERN = /\bFROM\s+(?:(\w+)\.)?(\w+)\b/gi;

const CLAUSE_KEYWORDS = new Set([
  'WHERE', 'AND', 'OR', 'ON', 'ORDER', 'GROUP', 'HAVING', 'LIMIT',
  'INNER', 'LEFT', 'RIGHT', 'OUTER', 'CROSS', 'JOIN',
]);

const RESERVED_FOR_ALIAS = new Set([
  'SELECT', 'SET', 'INTO', 'VALUES',
]);

export function collectUndefinedReferenceFacts(
  _ast: AST | AST[],
  text: string,
): ObservedFact[] {
  const commentRanges = findSqlCommentRanges(text);
  const cleanText = text.replace(/'[^']*'/g, '').replace(/"[^"]*"/g, '');

  const knownAliases = new Set<string>();
  const knownTables = new Set<string>();
  const tableMatch = new RegExp(TABLE_PATTERN.source, 'gi');
  let m: RegExpExecArray | null;

  while ((m = tableMatch.exec(cleanText)) !== null) {
    if (isInCommentRange(m.index, commentRanges)) continue;
    const schema = m[1];
    const table = m[2];
    const alias = m[3] || m[4] || '';
    knownTables.add(table);
    if (schema) knownTables.add(schema);
    if (alias && !CLAUSE_KEYWORDS.has(alias.toUpperCase())) {
      knownAliases.add(alias);
    }
  }

  const facts: ObservedFact[] = [];
  const qualRegex = new RegExp(QUALIFIED_REF_PATTERN.source, 'g');
  let qm: RegExpExecArray | null;

  while ((qm = qualRegex.exec(cleanText)) !== null) {
    if (isInCommentRange(qm.index, commentRanges)) continue;

    const qualifier = qm[1];
    if (qualifier === qm[2]) continue;

    if (RESERVED_FOR_ALIAS.has(qualifier.toUpperCase())) continue;
    if (CLAUSE_KEYWORDS.has(qualifier.toUpperCase())) continue;

    if (knownAliases.has(qualifier)) continue;
    if (knownTables.has(qualifier)) continue;

    const matchLine = text.slice(0, qm.index).split('\n').length;
    const matchLineStart = text.lastIndexOf('\n', qm.index) + 1;
    const matchColumn = qm.index - matchLineStart + 1;

    facts.push({
      id: `sql-detector:${FACT_KIND}:${matchLine}:${matchColumn}:${matchLine}:${matchColumn + qm[0].length}`,
      kind: FACT_KIND,
      appliesTo: 'block',
      range: {
        startLine: matchLine,
        startColumn: matchColumn,
        endLine: matchLine,
        endColumn: matchColumn + qm[0].length,
      },
      text: qm[0],
      props: {
        qualifier,
        reference: qm[0],
        knownAliases: [...knownAliases].sort().join(','),
        knownTables: [...knownTables].sort().join(','),
      },
    });
  }

  return facts;
}
