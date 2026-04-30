# Go Adapter

Minimal first-party Go adapter for deterministic polyglot support.

## Public API

- `analyzeGoFile(path, text): GoAnalysisResult`
- `goSourceAdapter`

## Supported Inputs

- extensions: `.go`
- language: `go`

## Current Behavior

This adapter uses `@critiq/adapter-shared` regex/polyglot helpers. It validates
one file at a time, collects lightweight scan state, runs shared fact
collectors, and returns an `AnalyzedFile` on success.

## Failure Behavior

Malformed input returns structured diagnostics instead of throwing raw parser
errors through the public API.

## Limits

Coverage is intentionally heuristic and text-driven. This adapter does not
perform full AST or type-aware analysis.
