---
"@critiq/adapter-sql": minor
---

Add SQL language adapter with 8 style fact collectors (`sql.style.*`). Includes `node-sql-parser`-based AST parsing, `analyzeSqlFile()`, and `sqlSourceAdapter` registered in the default source adapter registry. Supports SELECT, INSERT, UPDATE, DELETE, and common DDL statements across MySQL-style dialects.
