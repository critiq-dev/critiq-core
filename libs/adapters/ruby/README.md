# Ruby Adapter

Minimal first-party Ruby adapter for deterministic polyglot support.

## Public API

- `analyzeRubyFile(path, text): RubyAnalysisResult`
- `rubySourceAdapter`

## Supported Inputs

- extensions: `.rb`, `.erb` (for example `*.html.erb`)
- language: `ruby`

## Current Behavior

This adapter uses `@critiq/adapter-shared` regex/polyglot helpers. It validates
one file at a time, collects lightweight scan state, runs shared fact
collectors plus Rails-oriented collectors (strong parameters, CSRF posture,
redirects, unsafe HTML/render, Sidekiq Web mount, session/cookie misuse, and
request-tainted HTTP egress), and returns an `AnalyzedFile` on success.

## Failure Behavior

Malformed input returns structured diagnostics instead of throwing raw parser
errors through the public API.

## Limits

Coverage is intentionally heuristic and text-driven. This adapter does not
perform full AST or type-aware analysis. Rails CSRF and mass-assignment rules
use path and class-name heuristics (for example `ActionController::API` or
`controllers/api/`) to reduce noise on API-only surfaces; expect false positives
and false negatives on edge layouts.
