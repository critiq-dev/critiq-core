# SQL Adapter

First-party SQL adapter for deterministic polyglot support.

## Public API

- `analyzeSqlFile(path, text): SqlAnalysisResult`
- `sqlSourceAdapter`

## Supported Inputs

- extensions: `.sql`
- language: `sql`

## Current Behavior

This adapter uses `node-sql-parser` to parse SQL source text into an AST,
walks the AST to build observed nodes, and collects style-oriented facts
for the OSS rule catalog.

## Failure Behavior

Malformed input returns structured diagnostics instead of throwing raw parser
errors through the public API.

## Limits

Coverage is focused on SELECT, INSERT, UPDATE, DELETE, and common DDL statements.
Exotic or vendor-specific SQL syntax may not parse correctly.
