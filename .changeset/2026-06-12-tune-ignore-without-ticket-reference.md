---
'@critiq/adapter-rust': minor
---

feat: tune rust.testing.ignore-without-ticket-reference fact for precision

- Adds same-line comment detection after `#[ignore]` (e.g., `#[ignore] // JIRA-77`)
- Excludes Rust compiler/test infrastructure paths (`compiler/*/tests/`, `src/tools/*/tests/`, `tests/ui/`) from emitting the ignore-without-ticket-reference fact, since these paths have different `#[ignore]` conventions (feature-gated tests, crash tests, clippy fixtures, hardware tests)
- Other testing hygiene facts (thread-sleep, real-network) are still collected on these paths
