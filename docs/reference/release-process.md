# Release Process

This repository uses Changesets for version preparation and `vX.Y.Z` tags for
publishing `@critiq/cli`.

## Release Flow

1. Add a changeset for user-facing CLI/runtime changes.
2. Run `npm run version:packages` to cut the version commit.
3. Push the version commit.
4. Create and push a tag that matches `apps/cli/package.json`, for example
   `v0.1.0`.
5. The `release.yml` workflow verifies the repo, publishes `@critiq/cli`, and
   creates the GitHub release from Conventional Commit history.

## CI Gates

The release workflow requires:

- `npm ci`
- `npm run release:verify`
- `node scripts/check-release-tag.mjs "$GITHUB_REF_NAME"`

## Publishable Packages

- `@critiq/cli`

`@critiq/rules` now lives in the separate `critiq-rules` repository.

## Release Notes

Release notes must call out:

- CLI flags or JSON envelope changes
- rule loading or catalog resolution changes
- adapter behavior changes that affect CLI findings
- breaking compatibility for existing rule packs
