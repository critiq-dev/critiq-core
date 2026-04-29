# Project Analysis Invariants

`project-analysis` is the repo-level heuristic layer that runs after adapter
analysis and before rule evaluation.

The subsystem has three stages:

- `context.ts` extracts normalized per-file context such as imports, routes,
  frontend calls, detected function bodies, and guard markers.
- `fact-emitters.ts` adds synthetic project facts onto analyzed files for
  cross-file and heuristic rules.
- `runtime.ts` is the orchestration boundary that decides when diff-only
  heuristics run.

Keep these invariants stable when refactoring:

- Paths are repo-relative POSIX paths before cross-file correlation happens.
  Import resolution, route correlation, duplicate grouping, and source-to-test
  matching all assume that normalization has already happened.
- Offset-derived ranges are always 1-based and non-empty. When a match would
  otherwise collapse to zero width, range creation advances the end offset by
  one character so downstream findings always point at a visible span.
- Heuristics should rely on normalized range containment and explicit context
  properties instead of incidental adapter traversal order.
- Duplicate-code detection is intentionally conservative. It strips comments,
  normalizes whitespace, and only emits facts for function bodies that are both
  structurally large enough and duplicated across distinct files.
- Source-to-test correlation is filename-driven. `matchingTestPathsForSource()`
  is the canonical mapping, and fixture-like paths must remain excluded from
  missing-test heuristics.

If this subsystem grows further, keep new extraction helpers, heuristic
evidence builders, and fact emitters separate rather than re-expanding the
current modules.
