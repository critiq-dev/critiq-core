# @critiq/adapter-sql

## 0.1.0

### Minor Changes

- c5a9757: Add SQL language adapter with 8 style fact collectors (`sql.style.*`). Includes `node-sql-parser`-based AST parsing, `analyzeSqlFile()`, and `sqlSourceAdapter` registered in the default source adapter registry. Supports SELECT, INSERT, UPDATE, DELETE, and common DDL statements across MySQL-style dialects.
- c5a9757: Add 5 SQL fact collectors for batch 02 parity (SQL-L025, SQL-L026, SQL-L027, SQL-L029, SQL-L038):
  - `collectKeywordAsIdentifierFacts` (`sql.style.keyword-as-identifier`) — detects SQL keywords used as table aliases
  - `collectTrailingSelectCommaFacts` (`sql.style.trailing-select-comma`) — detects trailing commas before FROM
  - `collectUnusedTableAliasFacts` (`sql.style.unused-table-alias`) — detects table aliases never referenced
  - `collectUndefinedReferenceFacts` (`sql.correctness.undefined-reference`) — detects qualified column references to undefined tables/aliases
  - `collectUnqualifiedReferencesFacts` (`sql.style.unqualified-references`) — detects bare column references in multi-table queries
