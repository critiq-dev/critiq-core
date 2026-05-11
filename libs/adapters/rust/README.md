# Rust Adapter

Minimal first-party Rust adapter for deterministic polyglot support.

## Public API

- `analyzeRustFile(path, text): RustAnalysisResult`
- `rustSourceAdapter`

## Supported Inputs

- extensions: `.rs`
- language: `rust`

## Current Behavior

This adapter uses `@critiq/adapter-shared` regex/polyglot helpers. It validates
one file at a time, collects lightweight scan state, runs shared fact
collectors plus the `rust-framework-security` domain (Axum, Actix, Rocket, Warp,
SQLx/Diesel, and template-oriented heuristics), and returns an `AnalyzedFile`
on success.

## Failure Behavior

Malformed input returns structured diagnostics instead of throwing raw parser
errors through the public API.

## Limits

Coverage is intentionally heuristic and text-driven. This adapter does not
perform full AST or type-aware analysis.
