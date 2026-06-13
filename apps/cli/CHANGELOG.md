# @critiq/cli

## 0.4.0

### Minor Changes

- 1e2a570: Ship CloudFormation cfn-lint adapter support, 26 PHP analyzer parity adapter facts, and Ruby, Android, and Electron adapter facts. Prompt to install `@critiq/rules` when the configured catalog package is missing from local or global `node_modules`.
- 5fd870f: Add Wave 1 benchmark peer-gap facts for path-join user input, insecure HTTP server bootstrap, and Python path traversal user input.
- 5fd870f: Improve Wave 2 benchmark peer-gap SAST facts for contextual Python weak hashes, request-tainted dynamic code execution, Flask markup precision, taint-gated DOM HTML sinks, and user-controlled RegExp construction.
- 82fd4d5: Add batch-01 JavaScript parity adapter facts:
  - `language.new-symbol-instance` (JS-0233) — flags `new Symbol()` usage
  - `language.var-declaration` (JS-0239) — flags `var` declarations
  - `language.parse-int-on-number-literal` (JS-0253) — flags `parseInt`/`Number.parseInt` on number literals
  - `language.assignment-to-exports` (JS-0256) — flags `exports = ` reassignment
  - `language.callback-missing-error-handling` (JS-0254) — flags callbacks with unused error params
  - `language.callback-not-error-first` (JS-0255) — flags callbacks with wrong parameter order
  - `language.extraneous-import` (JS-0257) — flags unused import bindings

- 82fd4d5: Add batch-03 JavaScript parity adapter facts:
  - `language.invalid-shebang` (JS-0271) — flags shebang `#!` not on line 1 col 0
  - `language.deprecated-api` (JS-0272) — flags known deprecated API usage (`new Buffer()`, `url.parse()`, `domain.create()`, deprecated React lifecycle methods)
  - `language.invalid-async-await` (JS-0294) — flags `await`/`for await...of` outside async function
  - `language.ts-suppress-directive` (JS-0295) — flags `@ts-ignore`/`@ts-nocheck`/`@ts-expect-error` directives
  - `runtime.process-exit-control-flow` (JS-0270) — flags `process.exit()` in finally blocks or with reachable code after
  - `quality.banned-type` (JS-0296) — flags `any` type usage

- 82fd4d5: Add Vue Options API fact detectors (framework.vue.reserved-key-overwrite, framework.vue.computed-mutation, framework.vue.invalid-prop-type, framework.vue.data-object-declaration) to the TypeScript adapter for JavaScript parity batch 08.
- 0130a7f: feat: add 8 Ruby bug-risk fact collectors
  - duplicateCaseConditions: detect duplicate when conditions in case statements
  - duplicateMethodDefinitions: detect duplicate method definitions in same scope
  - eachWithObjectImmutableArg: detect each_with_object with immutable arguments
  - elseFollowedByExpression: detect expressions directly after else keyword
  - emptyEnsureBlock: detect ensure blocks without a body
  - emptyExpression: detect empty parenthesized expressions
  - emptyInterpolation: detect empty string interpolation `#{}`
  - whenBranchWithoutBody: detect when clauses without a body expression

- 0130a7f: Ruby adapter: add deprecated-big-decimal-new, symbol-boolean-name, circular-argument-reference, deprecated-class-methods, disjunctive-assignment-in-constructor fact collectors

  New `ruby.bug-risk.*` fact collectors in `@critiq/adapter-shared`:
  - `ruby.bug-risk.deprecated-big-decimal-new` — detects deprecated `BigDecimal.new` calls
  - `ruby.bug-risk.symbol-boolean-name` — detects `:true` and `:false` symbol literals
  - `ruby.bug-risk.circular-argument-reference` — detects method arguments with self-referencing defaults
  - `ruby.bug-risk.deprecated-class-methods` — detects deprecated `File.exists?`, `Dir.exists?`, and `iterator?`
  - `ruby.bug-risk.disjunctive-assignment-in-constructor` — detects redundant `||=` in `initialize`

- 0130a7f: Ruby adapter: add duplicate-constant-assignment, io-select-single-arg, bad-operand-order fact collectors

  New `ruby.bug-risk.*` fact collectors in `@critiq/adapter-shared`:
  - `ruby.bug-risk.duplicate-constant-assignment` — detects repeated constant assignments per file
  - `ruby.bug-risk.io-select-single-arg` — detects IO.select with single IO argument
  - `ruby.bug-risk.bad-operand-order` — detects literal-on-left binary expressions (Yoda conditions)

- 846919c: **async.infinite-loop fact**: Added YieldExpression detection to loopBodyHasExit

  Generator functions using `while(true) { yield value; }` are now correctly
  recognized as having an exit path (cooperative suspension via yield). This
  reduces false positives for generator-based infinite sequences.

- 846919c: feat(ruby): add batch 17 bug-risk and performance fact collectors (RB-RL1052-RB-RL1059)

  Adds 4 new bug-risk fact collectors:
  - `ruby.bug-risk.plain-method-instead-of-proc` (RB-RL1052)
  - `ruby.bug-risk.time-without-zone` (RB-RL1054)
  - `ruby.bug-risk.invalid-rails-env-predicate` (RB-RL1056)
  - `ruby.bug-risk.old-style-validation-macro` (RB-RL1057)

  Adds 2 new performance fact collectors:
  - `ruby.performance.enumerable-index-by` (RB-RL1058)
  - `ruby.performance.enumerable-index-with` (RB-RL1059)

  RB-RL1051 and RB-RL1055 are deferred (need AST-level analysis).

- 846919c: Add 7 new Ruby bug-risk fact collectors for RB-LI batch 13: self-assignment (RB-LI1092), identical-binary-operands (RB-LI1093), branches-without-body (RB-LI1094), trailing-comma-attribute (RB-LI1099), equal-instead-of-equal (RB-LI1100), invalid-integer-times (RB-LI1101), and constant-in-block (RB-LI1102).
- 846919c: ruby: add 8 rails framework bug-risk facts (RB-RL1001-RB-RL1008)
- 846919c: ruby: add 8 rails framework bug-risk facts (RB-RL1009-RB-RL1016)
- 846919c: Add 8 new Ruby bug-risk fact collectors for RB-RL batch 13: `ruby.bug-risk.deprecated-find-by-dynamic` (RB-RL1017), `ruby.bug-risk.enum-array-syntax` (RB-RL1018), `ruby.bug-risk.enum-duplicate-values` (RB-RL1019), `ruby.bug-risk.rails-env-equality` (RB-RL1020), `ruby.bug-risk.exit-in-app-code` (RB-RL1021), `ruby.bug-risk.rails-root-join` (RB-RL1022), `ruby.bug-risk.where-first-over-find-by` (RB-RL1023), `ruby.bug-risk.all-each-to-find-each` (RB-RL1024).
- 846919c: feat: tune testing.flaky-timer-in-test fact for precision
  - Removes `Date.now` and `performance.now` from wall-clock callee detection (these are performance measurement clocks, not flaky timers)
  - Adds micro-delay threshold: only emits flaky-timer fact for `setTimeout`/`setInterval` with delay argument > 50ms
  - No delay argument or numeric literal delay <= 50ms is treated as a micro-delay (event loop yielding) and skipped
  - Non-literal delay arguments (variables, expressions) are still flagged since the actual delay value is unknown

- 846919c: feat: tune security.iframe-missing-sandbox-attribute fact for precision
  - Skips iframes with `allowFullScreen` attribute — signals intentional trust (app marketplace embeds, payment gateways that need full browser capabilities)
  - Skips iframes with `allow` attribute — signals explicit CORS/permission policy management
  - Plain iframes without `sandbox`, `allowFullScreen`, or `allow` continue to be flagged

- 846919c: Ruby batch 09 (RB-RL) adapter facts
  - Add 7 new fact kinds: redundant-with-options-receiver, class-name-should-be-string, non-preferred-assert-falseness, relative-date-as-constant, inconsistent-request-referrer, inconsistent-safe-navigation-try, safe-navigation-with-blank
  - Extend irreversible-migration collector to detect irreversible operations (drop_table, remove_column, etc.) inside `def change` methods
  - Wire all new collectors into collectRubyBugRiskFacts
  - Alias codes: RB-RL1043 through RB-RL1050

### Patch Changes

- 7f0cce4: feat: add Java documentation fact collectors (java-doc.ts) for batch 05

  Adds four Javadoc fact collectors:
  - `java.doc.unmatched-parameter-tag` — detects @param tags that don't match method parameters
  - `java.doc.parameter-tag-no-description` — detects @param tags with no description
  - `java.doc.empty-javadoc-tag` — detects bare Javadoc block tags with no content
  - `java.doc.malformed-javadoc-comment` — detects doubled @@ symbols in Javadoc

  New domain file: `java-doc.ts` following the `go-doc.ts` pattern.

- 846919c: Ruby batch 05 (RB-LI-1001, 1002, 1003) ambiguous method invocation rules

  Add three new bug-risk fact collectors for ambiguous method invocation patterns:
  - ambiguous-block-association (RB-LI1001) - detects blocks with params after method arguments
  - ambiguous-operator-argument (RB-LI1002) - detects unary operators in method arguments
  - ambiguous-regexp-literal (RB-LI1003) - detects regex literals as method arguments

## 0.3.0

### Minor Changes

- Ship CloudFormation cfn-lint adapter support, 26 PHP analyzer parity adapter facts, and Ruby, Android, and Electron adapter facts. Prompt to install `@critiq/rules` when the configured catalog package is missing from local or global `node_modules`.

## 0.2.0

### Minor Changes

- Add TypeScript adapter facts for React maintenance and security JSX patterns (bind in props, prop spreads, lifecycle setState, direct state mutation, target=\_blank rel, duplicate attributes, and this in function components).
- Add TypeScript runtime and language security fact collectors for `with` statements, `arguments.callee`, `javascript:` URLs, native prototype extension, global native reassignment, non-Error throws, blocking dialogs, `process.exit`, and unsafe `__dirname` path concatenation.

## 0.1.0

### Minor Changes

- Rework the public CLI release contract around `@critiq/cli`, including the tag-driven npm publish workflow, GitHub release generation from conventional commits, and packaged release verification for the self-contained CLI artifact.
- Add `critiq check --format sarif` and `critiq check --format html` exports for security-platform ingestion and human-readable handoff workflows. Keep `audit` and `rules` format support scoped to `pretty|json` while documenting the new check-specific formats.
- Add `critiq audit secrets` and a parent `critiq audit --help` command. Extend `critiq check --format json` with an additive `secretsScan` field on the envelope. `critiq check` now runs an advisory secret scan (does not affect check exit code).
- Add `--staged` for `critiq check` and `critiq audit secrets` to scan `git diff --cached` index blobs. Extend `.critiq/config.yaml` with optional `secretsScan` (`ignorePaths`, `disabledDetectors`, `suppressFingerprints`). Ship sample `pre-commit` and `pre-push` hook scripts under `scripts/hooks/`.
- Add language facts for empty non-function blocks, catch-parameter reassignment, and regexp patterns that embed unusual ASCII control characters, backing three new `ts.correctness.*` catalog rules. Treat `regex.pattern` as pattern source text: decode common escapes (`\xNN`, `\uNNNN`, `\u{...}`, and `\v`/`\f`/`\b`) so controls such as `\x02` are detected while tab, LF, and CR remain allowed (including via `\t`, `\n`, `\r`, and matching hex escapes).

### Patch Changes

- Extend the TypeScript adapter with two new logging/disclosure facts and broaden recognized logger families. New facts `security.log-injection` and `security.debug-statement-in-source` cover request-controlled values flowing into pino, winston, bunyan, or consola messages and leftover `debugger;` / `console.trace()` calls in production paths. Existing `security.sensitive-data-in-logs-and-telemetry` and `security.information-leakage` now also recognize the broader pino/winston/bunyan/consola logger family sinks.
- Ship Python framework security facts for Django, DRF, Flask, and FastAPI via the regex polyglot adapter (`python-framework-security` helpers and `@critiq/adapter-python` wiring).
- Extend the Java adapter with new security fact collectors and Spring Boot support. Adds polyglot domains for insecure servlet cookies, open redirects, response-writer XSS, sensitive data egress, and Spring config debug exposure (`spring-config-debug-exposure`), wired through `@critiq/adapter-java` and shared polyglot analysis.
- Add React error boundary and accessibility fact collectors to the TypeScript adapter. New `react-accessibility` custom facts cover missing error boundaries, missing accessibility labels, derived-state-from-props, index-as-key in dynamic lists, and uncontrolled-to-controlled input transitions, with project-analysis fact emitters wired into the runtime.
- Add TypeScript adapter security fact collectors for Angular, NestJS, and Next.js. New custom facts cover Angular DOM sanitizer bypass (`angular-dom-sanitizer`), NestJS hardening (`nestjs-security`: Helmet ordering, global validation pipe, throttling, whitelist), Next.js Server Actions local auth (`next-server-actions`), and shared `node-framework-bootstrap` / `react-next-best-practices` helpers used by these detectors.
- Add Go and framework security fact collectors through the shared polyglot `go-security` domain and `@critiq/adapter-go` wiring. Includes Go open redirect and SSRF facts (reused by existing multi-language rules), Go-specific sensitive egress, tar path traversal, net/http timeout posture, Gin CORS/proxy/binding checks, Echo/Fiber binding and upload checks, template trusted-type misuse, plus broader Go request-source and SQL helper (`Raw`/`RawContext`) coverage.
- Add Java Spring framework security fact collectors (`java-framework-security` in `@critiq/adapter-shared`), wire them from `@critiq/adapter-java`, extend Java scan extensions with Spring Boot `application`/`bootstrap` `*.yml` plus `.html`/`.htm` for template-oriented findings, and stop folding wildcard actuator exposure into `security.spring-debug-exposure` (debug and verbose logging only there).
- Add PHP framework security fact coverage on top of the existing polyglot baseline by wiring new shared collectors into `@critiq/adapter-php`. The shipped slice includes Laravel mass assignment, sensitive CSRF exclusions, unsafe raw Blade output, Symfony debug/CSRF posture checks, WordPress nonce-capability and unprepared SQL signals, plus session/cookie hardening, wildcard CORS-with-credentials, insecure plaintext transport, unsafe upload handling, and sensitive data egress facts.
- Add Ruby on Rails security fact collectors to the Ruby adapter via the shared polyglot `ruby-rails-security` domain. Covers strong-parameter misuse, CSRF protection disabled, unsafe HTML output, unsafe render, unsafe session/cookie stores, detailed-exceptions enabled, open redirects, sensitive data egress, and unauthenticated Sidekiq Web mounts.
- Add Rust framework security fact collectors through the shared polyglot `rust-framework-security` domain and `@critiq/adapter-rust` wiring for Axum body limits and tower-http CORS, Actix CORS with credentials, Rocket handler panics and raw HTML, Warp async blocking and unwraps, SQLx/Diesel `format!` interpolation, and Tera-style template context inserts without sanitization.
- Extend the TypeScript adapter public security collectors with stronger Node.js framework hardening signals, including Express default-session and cookie sameSite posture, Express parser suppression in explicit dev-only branches, Fastify public listen posture without `trustProxy`, Fastify route-level excessive `bodyLimit` checks, Apollo Server dev tooling plugin exposure heuristics, internal-only suppression for Apollo missing-query-limit posture, GraphQL multipart upload posture when Apollo CSRF is explicitly disabled, NestJS sensitive-route SkipThrottle compensating-control suppression, Nuxt `runtimeConfig.public` secret-shaped keys, and Astro `vite.define` wiring of secret-like `process.env` values into `import.meta.env.PUBLIC_*` keys.
- Add public parity runtime support for dependency-policy facts, shared processor egress recipes, cross-language filesystem depth facts, and complete default adapter package declarations.
- Extend the TypeScript adapter for `ts.react.no-effect-fetch-without-cancellation` (and related facts): treat GraphQL client-style `.query`/`.mutate` calls and `graphql-request` imports as network sources, honor Apollo-style `context.fetchOptions.signal`, suppress when the enclosing component uses `useLoaderData` / `useRouteLoaderData`, and respect common stale-response guard patterns (`cancelled`/`ignore` flags with cleanup).
- Helmet option hardening, static `dotfiles: 'allow'`, unsafe CSP response literals, Ajv insecure configuration, `parseString` on untrusted XML, Express production error disclosure, request-driven array indexing, user-controlled static mounts, legacy `Buffer()` usage, React iframe `sandbox`, JWT `none` signing, and narrowed Electron `shell.openExternal` heuristics.
- Expand public performance fact coverage across TypeScript custom detectors, project analysis emitters, and shared polyglot adapters. Add cross-language runtime eligibility improvements and adapter test coverage for new performance parity signals.
- Add TypeScript and polyglot quality-maintainability fact emitters for the quality rule expansion, including project-level wide-public-surface, barrel-cycle, and dead-export analysis hooks.
- Extend the public TypeScript and JavaScript adapter with six React JSX parity fact kinds covering legacy lifecycle methods, `findDOMNode`, string refs, image alt text, positive `tabIndex`, and click-only custom controls.
- Add TypeScript testing hygiene custom facts, project-scoped edge-case and production-or-test-boundary emitters, shared test-path helpers and polyglot testing-hygiene collectors, and align sandbox-style scans with `includeTests` where needed for rule validation.
- Ship public-directory `JS-0xxx` core-correctness facts via the bundled TypeScript adapter: `language.assignment-in-condition`, `language.duplicate-function-parameter`, `language.duplicate-object-key`, `language.duplicate-switch-case`, `language.async-promise-executor`, `language.assignment-to-import-binding`, `language.self-assignment`, `language.identical-comparison-operands`, and `language.duplicate-import-source`, collected from `collectTypescriptCoreLanguageCorrectnessFacts`.
- Emit additional React UI facts for external-analyzer parity: invalid anchor href targets, `aria-activedescendant` owners that are not keyboard focusable, widget roles without a non-negative tabIndex, semantic text elements with interactive roles, combined click and keyboard handlers without a widget role, pointer or key handlers without click or widget roles, and deprecated `react-dom` root APIs plus `createFactory`. Extend JSX element and event helper utilities accordingly.
