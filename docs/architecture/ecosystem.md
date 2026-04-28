# Critiq Ecosystem

This document explains where `critiq-core` sits in the broader Critiq
ecosystem and why we keep the boundary explicit.

## The Layers

Think about Critiq as three layers:

1. authored rule packs and catalogs
2. the open confidence core
3. the hosted and Pro product layer

`critiq-core` owns the second layer and supports local workflows around the
first.

## What `critiq-core` Owns

This repository is the public, inspectable runtime that developers can adapt
for their own repositories and automation.

It owns:

- the public rule DSL contract
- YAML loading and source-aware diagnostics
- semantic validation for rules
- canonical normalized rule IR and hashing
- deterministic rule evaluation
- canonical finding contracts and JSON Schema artifacts
- repository-level config loading
- catalog package resolution and preset filtering
- the reusable `check` runtime
- the published `critiq` CLI
- fixture-backed `RuleSpec` execution
- first-party adapters, including the TypeScript reference adapter and early
  polyglot adapters

## What Lives Adjacent To This Repo

Some important pieces are intentionally separate:

- `critiq-rules`
  The maintained OSS rule catalog and starter examples consumed by
  `critiq check`.
- consumer repositories
  The application code, local rules, and CI pipelines that adopt Critiq.
- the hosted Critiq product and future Pro layer
  Orchestration, collaboration, governance, and broader confidence workflows
  built on top of the OSS core.

## What Does Not Belong Here

We intentionally keep these concerns out of `critiq-core`:

- account and tenant management
- billing or commercial packaging logic
- hosted review queues and browser application state
- organization-wide dashboards and historical reporting
- remote execution schedulers that do not need to live in the OSS runtime
- product-only governance workflows and collaboration features

## Why The Split Matters

We want the confidence engine itself to remain public.

That boundary matters because it lets developers:

- inspect why a finding exists instead of trusting hidden review behavior
- adapt the runtime without copying product code
- test rules locally before rolling them into CI
- keep findings, diagnostics, and rule contracts stable across environments
- build their own workflows on top of the same deterministic engine

It also keeps us honest as package owners. If confidence depends on secret
runtime behavior, the OSS layer is not really portable.

## How Pro Fits

Critiq Core is the open source confidence foundation.

The hosted Critiq product and future Pro offerings are where we expect broader
pipeline confidence to compound: orchestration, collaboration, policy
governance, review memory, team visibility, and confidence signals that span
more than a single local run.

The important point is that those layers should build on the open contracts in
this repository rather than replace them with a different engine.

## Typical Flows

### Local Developer Flow

1. add or update `.critiq/config.yaml`
2. run `critiq check` against a repository or diff
3. author or adapt local rules when the default catalog is not enough
4. validate, explain, and test those rules with `critiq rules ...`

### Team CI Flow

1. commit the Critiq config to the repository
2. run `critiq check` in pull request automation
3. optionally validate and test local rule packs in the same workflow
4. use JSON output as an artifact or downstream machine input

### Product And Pro Flow

1. reuse the OSS contracts and runtime behavior from `critiq-core`
2. orchestrate review across repositories, teams, and pipelines
3. add governance, collaboration, and organizational confidence layers on top

## Where To Start Next

- New user: [../../README.md](../../README.md)
- First run: [../guides/getting-started.md](../guides/getting-started.md)
- CLI details: [../reference/cli.md](../reference/cli.md)
- Package ownership: [./repo-map.md](./repo-map.md)
- Contributor workflow: [../../CONTRIBUTING.md](../../CONTRIBUTING.md)
