# Selectors and Applicability Reference

`CRQ-OSS-09` adds file-level applicability checks in
`@critiq/core-rules-engine`.

## API

- `evaluateRuleApplicability(rule, analyzedFile)`

## Result Shape

- `{ applicable: true }`
- `{ applicable: false, reason }`

## Stable Skip Reasons

- `language-mismatch`
- `path-not-included`
- `path-excluded`
- `no-file-changes`

## Precedence

Applicability is evaluated in this order:

1. language
2. include globs
3. exclude globs
4. `changedLinesOnly`

Exclude globs override include globs.

## Changed Lines

The file-level `changedLinesOnly` check is a fast skip only.

The rule is skipped when:

- `changedLinesOnly` is `true`
- and `changedRanges` is absent or empty

Candidate-node filtering still happens later during predicate evaluation.
