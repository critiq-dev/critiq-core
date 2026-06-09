---
"@critiq/adapter-shared": minor
"@critiq/adapter-go": minor
---

Add two new security fact collectors for Go (batch 09):

- `go.security.incomplete-hostname-regex` — detects unanchored or overly
  permissive regex patterns used for hostname validation (GO-S1016).
- `go.security.squirrel-unsafe-quoting` — detects `squirrel.Expr` calls
  with `fmt.Sprintf` interpolation that allows SQL injection (GO-S1017).
