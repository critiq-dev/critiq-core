# Release Process

This repository uses Changesets for coordinated versioning.

## CI Gates

The release workflow requires:

- `npm ci`
- `npm run verify`
- `npm run check:schema-drift`
- `npm run check:package-exports`
- `npm run check:package-contents`
- `npm run release:dry-run`

## Publishable Packages

- `critiq`
- `@critiq/check-runner`
- `@critiq/core-finding-schema`
- `@critiq/core-rules-dsl`
- `@critiq/core-diagnostics`
- `@critiq/core-ir`
- `@critiq/core-rules-engine`
- `@critiq/adapter-typescript`
- `@critiq/testing-harness`

`@critiq/rules` now lives in the separate `critiq-rules` repository.

## Release Notes

Release notes must call out:

- finding schema changes
- rule DSL changes
- CLI flags or JSON envelope changes
- adapter property-path compatibility changes
