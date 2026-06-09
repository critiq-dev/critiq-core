import type { ObservedFact } from '@critiq/core-rules-engine';
import type { AST } from 'node-sql-parser';

import { collectAmbiguousDistinctFacts } from './ambiguous-distinct';
import { collectColumnExpressionWithoutAliasFacts } from './column-expression-without-alias';
import { collectDistinctWithParenthesisFacts } from './distinct-with-parenthesis';
import { collectDuplicateTableAliasesFacts } from './duplicate-table-aliases';
import { collectImplicitColumnAliasFacts } from './implicit-column-alias';
import { collectImplicitTableAliasFacts } from './implicit-table-alias';
import { collectInconsistentCapitalizationFacts } from './inconsistent-capitalization';
import { collectInconsistentKeywordCaseFacts } from './inconsistent-keyword-case';
import { collectKeywordAsIdentifierFacts } from './keyword-as-identifier';
import { collectTrailingSelectCommaFacts } from './trailing-select-comma';
import { collectUnusedTableAliasFacts } from './unused-table-alias';
import { collectUndefinedReferenceFacts } from './undefined-reference';
import { collectUnqualifiedReferencesFacts } from './unqualified-references';

export function collectSqlFacts(
  ast: AST | AST[],
  text: string,
): ObservedFact[] {
  return [
    ...collectInconsistentKeywordCaseFacts(ast, text),
    ...collectImplicitTableAliasFacts(ast, text),
    ...collectImplicitColumnAliasFacts(ast, text),
    ...collectColumnExpressionWithoutAliasFacts(ast, text),
    ...collectInconsistentCapitalizationFacts(ast, text),
    ...collectDistinctWithParenthesisFacts(ast, text),
    ...collectDuplicateTableAliasesFacts(ast, text),
    ...collectAmbiguousDistinctFacts(ast, text),
    ...collectKeywordAsIdentifierFacts(ast, text),
    ...collectTrailingSelectCommaFacts(ast, text),
    ...collectUnusedTableAliasFacts(ast, text),
    ...collectUndefinedReferenceFacts(ast, text),
    ...collectUnqualifiedReferencesFacts(ast, text),
  ];
}

export { collectInconsistentKeywordCaseFacts } from './inconsistent-keyword-case';
export { collectImplicitTableAliasFacts } from './implicit-table-alias';
export { collectImplicitColumnAliasFacts } from './implicit-column-alias';
export { collectColumnExpressionWithoutAliasFacts } from './column-expression-without-alias';
export { collectInconsistentCapitalizationFacts } from './inconsistent-capitalization';
export { collectDistinctWithParenthesisFacts } from './distinct-with-parenthesis';
export { collectDuplicateTableAliasesFacts } from './duplicate-table-aliases';
export { collectAmbiguousDistinctFacts } from './ambiguous-distinct';
export { collectKeywordAsIdentifierFacts } from './keyword-as-identifier';
export { collectTrailingSelectCommaFacts } from './trailing-select-comma';
export { collectUnusedTableAliasFacts } from './unused-table-alias';
export { collectUndefinedReferenceFacts } from './undefined-reference';
export { collectUnqualifiedReferencesFacts } from './unqualified-references';
