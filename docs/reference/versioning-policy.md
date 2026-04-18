# Versioning Policy

Critiq v0 uses package semver plus explicit payload/version fields where the
wire contract needs stronger guarantees.

## Compatibility Surface

- `@critiq/core-finding-schema`
  - semver for the package
  - `schemaVersion` for emitted finding payloads
- `@critiq/core-rules-dsl`
  - semver for the package
  - `apiVersion` and `kind` for authored rule compatibility
- `@critiq/adapter-typescript`
  - semver only for the documented observation and property-path surface
- `@critiq/testing-harness` and `critiq`
  - semver for documented commands, flags, JSON envelopes, and RuleSpec behavior

## Internal Surface

`@critiq/core-ir` is repo-internal. Its shape may change as long as repo
consumers are updated together.

## Deprecation

- document the deprecation
- include it in release notes
- keep deprecated behavior for at least one minor release unless explicitly
  marked experimental pre-1.0
