# Adapter Authoring Guide

This document defines how adapters are structured in `critiq-core`, what
belongs in each package, when to use shared adapter code, and how we decide
what stays in OSS versus what belongs in the Pro repository.

The TypeScript adapter is currently the most complete implementation and should
be treated as the reference for capability depth, not as a perfect reference
for file layout. Some existing files predate the conventions in this guide.
Those legacy files should not be used as the standard for new work.

## What An Adapter Owns

An adapter is responsible for deterministic language-specific source analysis.
Its job is to accept a file path and source text, then return either:

- a successful `AnalyzedFile`
- a structured failure with diagnostics

Adapters should:

- parse or validate one source file at a time
- emit deterministic observations and facts
- keep their public surface small and stable
- avoid product-specific or hosted-only behavior

Adapters should not:

- own CLI composition
- own repository orchestration
- own hosted workflows
- depend on Pro-only code

## Standard Package Layout

Each adapter package should live under `libs/adapters/<language>`.

```text
libs/adapters/<language>/
  README.md
  project.json
  package.json
  jest.config.cts
  tsconfig.json
  tsconfig.lib.json
  tsconfig.spec.json
  eslint.config.mjs
  src/
    index.ts
    lib/
      <language>.ts
      <feature>.ts
      <feature>.spec.ts
      <subsystem>/
        index.ts
        <helper>.ts
        <helper>.spec.ts
```

Use this structure consistently:

- `src/index.ts`
  The public package entrypoint. It should re-export the adapter's public API
  and nothing else.
- `src/lib/<language>.ts`
  The composition root for the adapter. This should wire the adapter together,
  define its public exports, and delegate real work to smaller files.
- `src/lib/<feature>.ts`
  A focused detection, parser helper, collector, or adapter subsystem.
- `src/lib/**/*.spec.ts`
  Unit tests colocated with the behavior they verify.
- `README.md`
  Package-level behavior, supported inputs, important limits, and public API.

## Adapter Styles In This Repository

We currently have two adapter styles.

### ESTree Or AST-Backed Adapters

`libs/adapters/typescript` is the reference example for a richer adapter.

This style typically:

1. parses source into an AST
2. builds observed nodes and ranges
3. adds semantic structures such as control flow
4. runs focused fact collectors
5. returns an `AnalyzedFile`

Use this style when the language adapter needs deeper structural reasoning.

### Shared Polyglot Or Regex-Driven Adapters

Adapters such as Go, Java, PHP, Python, Ruby, and Rust currently use shared
polyglot helpers from `@critiq/adapter-shared`.

This style typically:

1. validates or lightly parses the source text
2. collects intermediate scan state
3. runs reusable fact collectors
4. returns an `AnalyzedFile` through the shared adapter pipeline

Use this style when we want broad deterministic coverage with simpler
language-specific heuristics.

## Public API Expectations

An adapter package should export a minimal public surface.

Typical exports are:

- `analyze<Language>File(path, text)`
- `<language>SourceAdapter`
- explicit result types when useful to callers

Do not export internal helpers from `src/index.ts` just because they exist.
Keep private implementation details inside `src/lib`.

Failures must return structured diagnostics. Do not throw raw parser exceptions
through the public adapter API.

## File And Function Organization Rules

These are the default rules for new work and for touched code.

### File Size

- Treat `1000` lines of code as a soft ceiling for implementation files.
- If a file approaches or exceeds that size, split it by concern.
- Large orchestration files should become thin coordinators over smaller
  modules.

### One Helper Per File

- If you extract a helper or utility function, put it in its own file.
- Name the file after the function or the exact concern it owns. <funtion>.util.ts
- Use folder-level `index.ts` files only as aggregators, not as places to hide
  unrelated logic.

Good:

```text
custom-facts/
  collect-open-redirect-facts.ts
  collect-open-redirect-facts.spec.ts
  is-external-redirect-target.ts
  is-external-redirect-target.spec.ts
  index.ts
```

Avoid:

```text
custom-facts/
  utils.ts
  helpers.ts
  misc.ts
```

### Comments And Intent

- Add comments to functions to document intent.
- Every exported function should have a short doc comment.
- Non-obvious internal functions should also explain why they exist or what
  invariant they protect.
- Do not add noise comments that only restate the code mechanically.

The goal is to explain intent, not syntax.

### Typing Rules

- Everything should be typed.
- `any` should be avoided.
- Prefer `unknown` plus narrowing when a value is not yet trusted.
- Prefer explicit interfaces, discriminated unions, and type guards over loose
  object access.
- Use `satisfies` when it clarifies the shape without widening the value.

## Where Code Belongs

Put code in the narrowest place that still reflects its ownership.

### Keep It In The Adapter Package When

- it is specific to one language
- it depends on one parser or AST model
- it expresses a detection that only exists for one adapter
- it is a helper that only one adapter needs

### Move It To `libs/adapters/shared` When

- at least two adapters use it already or clearly need it
- it is parser-agnostic or text-analysis-agnostic
- it improves shared polyglot behavior without leaking one adapter's internals
- it represents a stable reusable building block such as scan state, fact
  collection, or analyzed-file assembly

### Do Not Put It In `libs/adapters/shared` When

- it is TypeScript ESTree-specific
- it only serves one adapter
- it mixes product policy with reusable language analysis
- it would force other adapters to depend on concepts they do not use

## How To Contribute To `@critiq/adapter-shared`

`libs/adapters/shared` is for reusable adapter infrastructure, not for dumping
miscellaneous helpers.

When adding shared code:

1. make sure the abstraction is genuinely reusable
2. keep the API deterministic and well typed
3. add unit tests in the shared package
4. export it explicitly through `src/lib/shared.ts`
5. re-export it from `src/index.ts` if it is part of the package surface

Good candidates for shared code:

- analyzed-file builders
- generic scan-state utilities
- reusable fact collectors
- parser-agnostic text and delimiter helpers

Poor candidates for shared code:

- one-off TypeScript AST walkers
- single-adapter naming vocabularies
- commercial feature toggles
- convenience wrappers with only one caller

## Testing Expectations

We should always add unit testing to adapters where applicable.

At minimum:

- add tests for new detectors and fact collectors
- add tests for syntax validation behavior
- add tests for helper functions that encode business logic
- add regression tests for bugs once fixed

Test placement rules:

- colocate tests next to the code they verify
- prefer narrow fixture inputs over oversized snapshots
- assert on emitted facts, diagnostics, and ranges explicitly

Before finishing adapter work, run the narrowest useful checks first and then
the broader repo gate as needed.

Typical commands:

```bash
npm run nx -- test <adapter-project>
npm run nx -- typecheck <adapter-project>
```

Final gate for meaningful adapter changes:

```bash
npm run verify
```

## OSS Versus Pro Responsibilities

Some adapter functionality belongs in this OSS repository, and some belongs in
the Pro repository.

Keep functionality in OSS when it is:

- deterministic
- broadly useful
- language-analysis focused
- safe to publish as part of the public core contract

Move functionality to Pro when it is:

- commercially differentiating
- product-specific
- hosted or orchestration heavy
- dependent on private heuristics, proprietary signals, or paid workflows

The preferred split is:

- OSS defines stable language-analysis primitives, facts, and contracts
- Pro composes premium behavior on top of those stable OSS contracts

Do not introduce direct dependencies from OSS adapters to Pro code.

## Adapter Change Checklist

Before considering adapter work complete, confirm:

- the code lives in the right adapter package
- reusable logic was only moved to shared when it truly has shared ownership
- new helpers were split into one function per file
- large files were broken up when they crossed the maintainability threshold
- functions are documented with intent comments
- no `any` was introduced
- unit tests cover the new behavior
- the package README and relevant reference docs were updated if the public
  surface changed

## Practical Guidance For New Adapters

When creating a new adapter:

1. start with the standard package layout
2. keep `src/index.ts` minimal
3. make `src/lib/<language>.ts` a thin composition layer
4. build focused helpers and detectors in separate files
5. add tests as each capability is introduced
6. only promote abstractions into `@critiq/adapter-shared` once reuse is real

If you are unsure where a piece of code belongs, default to keeping it local to
the adapter until reuse becomes obvious.
