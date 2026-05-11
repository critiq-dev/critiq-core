# Java Adapter

Minimal first-party Java adapter for deterministic polyglot support.

## Public API

- `analyzeJavaFile(path, text): JavaAnalysisResult`
- `javaSourceAdapter`

## Supported Inputs

- extensions: `.java`, `.properties`, Spring Boot `application*.yml` / `bootstrap*.yml`, and `.html` / `.htm` (templates analyzed with the same `java` language tag)
- language: `java`

Note: `.yaml` is intentionally omitted so repository tooling such as `.critiq/config.yaml` is not routed through this adapter.

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
