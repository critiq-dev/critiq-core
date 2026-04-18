# Finding Builder Reference

`CRQ-OSS-11` adds finding construction in `@critiq/core-rules-engine`.

## API

- `buildFinding(rule, analyzedFile, match, options?)`

## Behavior

`buildFinding(...)`:

- renders user-facing message fields from the normalized emit spec
- builds primary location data from the matched node range
- emits at least one evidence item for the matched node
- computes deterministic `sha256:` fingerprints
- fills finding provenance with engine kind, version, and timestamp
- validates the final output with `validateFinding(...)`

## Result Shape

- `{ success: true, finding }`
- `{ success: false, issues }`

## Fingerprints

- `fingerprints.primary` is derived from normalized rule hash, file path, match
  range, node kind, and captures
- `fingerprints.logical` is derived from normalized rule hash, file path, and
  node kind

## Provenance Defaults

- `engineKind`: `critiq-reviewer`
- `engineVersion`: `0.0.1`
- `generatedAt`: current ISO timestamp unless overridden

## Evidence

The v0 builder includes one evidence item with:

- `kind: match-node`
- a human-readable label
- `path`
- `excerpt`
- `range`
