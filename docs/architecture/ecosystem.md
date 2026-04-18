# Critiq Ecosystem

This document explains how this repository fits into the broader `critiq.dev`
system.

## Mental Model

Think of Critiq as three layers:

1. **Authored rule layer**
   Rules, RuleSpec files, examples, and local author workflows.
2. **Open runtime layer**
   Contracts, validation, normalization, evaluation, findings, adapters, CLI,
   and test harness.
3. **Hosted product layer**
   Product UX, persistence, tenancy, remote execution, account features, and
   hosted orchestration.

This repository owns layers 1 and 2.

## What Lives Here

This repo provides the stable building blocks that both local tooling and the
hosted product should share:

- the public rule DSL
- the canonical finding schema
- diagnostics and source spans
- YAML loading with source mapping
- semantic validation
- normalized internal rule IR
- the deterministic rules engine
- the example TypeScript/JavaScript adapter
- the local CLI
- the RuleSpec harness
- the starter example pack

## What Does Not Live Here

These concerns are intentionally out of scope for this repository:

- account management
- billing or tenant ownership
- hosted rule storage
- browser application state
- remote execution scheduling
- product-specific dashboards and review flows
- service-side orchestration that does not belong in the OSS runtime

## Why The Split Matters

The boundary exists so that:

- authored rules do not depend on hosted-only behavior
- emitted findings have a stable contract
- adapters and rules can be tested locally
- hosted product code composes the OSS runtime instead of forking it
- contributors can inspect and extend deterministic behavior without needing the
  full product stack

## Typical Flows

### Local Author Flow

1. Write or edit a `.rule.yaml`.
2. Run `validate`.
3. Run `explain`.
4. Add or update a `.spec.yaml`.
5. Run `test`.

### Hosted Product Flow

1. Accept or retrieve authored rules.
2. Reuse the shared contracts and validation pipeline from this repo.
3. Analyze source files through adapters.
4. Evaluate rules and emit findings.
5. Present results in hosted product UX.

The hosted flow should reuse the OSS contracts instead of redefining them.

## Where To Start In This Repo

- New user: [README.md](../../README.md)
- Contributor: [CONTRIBUTING.md](../../CONTRIBUTING.md)
- Architecture: [repo-map.md](./repo-map.md)
- Rule author: [write-your-first-rule.md](../guides/write-your-first-rule.md)
