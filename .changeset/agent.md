# Changeset Agent Rules

Follow these rules for every file in this directory.

## 1) Immutability after commit

- A changeset file is immutable once committed.
- Do not edit, rename, or delete committed changeset files.
- If a correction is needed, add a new changeset file instead.

## 2) Required file naming format

- Every changeset filename must be: `yyyy-mm-dd-<slug>.md`
- `yyyy-mm-dd` is the authored date in UTC.
- `<slug>` is a short, kebab-case description.
- Example: `2026-05-09-log-injection-and-debug-statements.md`
- The Changesets CLI may generate a random three-word filename; rename it before commit.

## 3) When a changeset is required

Create a changeset whenever a change affects:

- finding schema compatibility
- rule DSL compatibility
- CLI flags or JSON envelopes
- adapter property-path guarantees
- package exports or published contents

Use `npm run changeset` to create the entry.

## 4) Operational expectation

- Keep date-prefixed naming so `.changeset/` remains sortable by authoring date.
- This helps identify stale pending entries quickly.
