---
'@critiq/adapter-ruby': minor
'@critiq/adapter-shared': minor
'@critiq/cli': minor
---

feat: add 8 Ruby bug-risk fact collectors

- duplicateCaseConditions: detect duplicate when conditions in case statements
- duplicateMethodDefinitions: detect duplicate method definitions in same scope
- eachWithObjectImmutableArg: detect each_with_object with immutable arguments
- elseFollowedByExpression: detect expressions directly after else keyword
- emptyEnsureBlock: detect ensure blocks without a body
- emptyExpression: detect empty parenthesized expressions
- emptyInterpolation: detect empty string interpolation `#{}`
- whenBranchWithoutBody: detect when clauses without a body expression
