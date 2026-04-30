# Versioning Policy

Critiq v0 uses package semver plus explicit payload/version fields where the
wire contract needs stronger guarantees.

## Compatibility Surface

- `@critiq/cli`
  - semver for documented commands, flags, JSON envelopes, and packaged runtime
  - `schemaVersion` for emitted finding payloads
  - `apiVersion` and `kind` for authored rule compatibility consumed by the CLI

`@critiq/rules` is versioned independently in the separate `critiq-rules`
repository.

## Internal Surface

The low-level `@critiq/*` workspace libraries in this repository are internal
implementation details. They may change as long as `@critiq/cli` compatibility
is preserved.

## Deprecation

- document the deprecation
- include it in release notes
- keep deprecated behavior for at least one minor release unless explicitly
  marked experimental pre-1.0
