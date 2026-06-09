import { Parser, type AST } from 'node-sql-parser';

const parser = new Parser();

export interface ParseSuccess {
  success: true;
  ast: AST | AST[];
}

export interface ParseFailure {
  success: false;
  error: string;
}

export type ParseResult = ParseSuccess | ParseFailure;

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

export function isSqlKeyword(word: string): boolean {
  return SQL_KEYWORDS.has(word.toUpperCase());
}

export function parseSql(text: string): ParseResult {
  if (text.trim().length === 0) {
    return { success: false, error: 'Empty SQL input' };
  }

  try {
    const ast = parser.astify(text, { database: 'MySQL' });
    return { success: true, ast };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown parse error';
    if (message.includes('but "u" found')) {
      return { success: false, error: 'SQL parser error: implicit aliases not supported without SELECT wrapper' };
    }
    return { success: false, error: message };
  }
}
