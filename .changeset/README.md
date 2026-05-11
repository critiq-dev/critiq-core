# Changesets

This repository uses Changesets for release coordination across the publishable
Critiq packages and the `critiq` CLI.

Create a changeset whenever a change affects:

- finding schema compatibility
- rule DSL compatibility
- CLI flags or JSON envelopes
- adapter property-path guarantees
- package exports or published contents

## File naming

Use **`yyyy-mm-dd-<slug>.md`** for every changeset file, where:

- `yyyy-mm-dd` is the date the changeset was authored (UTC).
- `<slug>` is a short, kebab-case description of the change.

Example: `2026-05-09-log-injection-and-debug-statements.md`.

`npm run changeset` (the Changesets CLI) generates a random three-word filename
by default — **rename it** to the `yyyy-mm-dd-<slug>.md` form before committing.
Date-prefixed filenames keep `.changeset/` sortable by authoring order and make
it obvious at a glance which pending entries are stale.
