# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `critiq-core`, please report it
responsibly via [GitHub's private vulnerability
reporting](https://github.com/critiq-dev/critiq-core/security/advisories/new)
instead of opening a public issue.

You should receive a response within 48 hours. Please include:

- A description of the vulnerability
- Steps to reproduce it
- Any relevant version, configuration, or rule-catalog information

## Scope

`critiq-core` (`@critiq/cli`) is a static analysis tool that reads source
files, configuration files (`.critiq/config.yaml`), and rule catalogs
(`@critiq/rules` or local `.critiq/rules/`). It does **not** execute user code,
make network requests on its own, or modify files on disk (it only writes
reports to stdout or to the output file you explicitly pass via `--output`).

The analysis runs entirely in-process on the local machine or CI runner. It
parses source files through language-specific adapters (TypeScript, Go, Java,
Python, PHP, Ruby, Rust, CloudFormation, SQL) and matches the resulting AST /
IR against a rule catalog. No user code is evaluated, imported, or executed
during analysis.

## Threat Model

The primary security boundary is the project root you pass to `critiq check` (or
the directory where `.critiq/config.yaml` is found when you omit it). Critiq
walks files under that root and reads only source files, configuration, and
rule-catalog content found within it.

### Config-sourced paths

Configuration fields that accept file-system paths (`ignorePaths`,
`catalog.package`, `catalog.rulesPath`) are constrained to the project root.
Rule-catalog packages referenced by name (e.g. `@critiq/rules`) resolve through
the npm dependency tree, not through arbitrary file-system paths.

When a catalog rules-path is configured, Critiq resolves it relative to the
config directory and rejects absolute paths, `..` traversal segments, and paths
that escape the workspace. Any invalid path causes `critiq check` to exit with
code 2 before walking the filesystem.

### Rule catalog trust

`critiq check` loads rules from an npm package (`@critiq/rules` by default) or
from local `.critiq/rules/` files. Rule YAML is validated against the public DSL
schema at load time; malformed rules are rejected before analysis begins. Treat
the rule catalog as trusted input — a malicious rule file could inject arbitrary
facts into the analysis output, though it cannot escape the process.

In CI, pin the `@critiq/rules` version in your `package.json` so an un-reviewed
catalog version is not pulled in automatically.

### CLI binary supply chain

`@critiq/cli` ships as an npm package with pure JavaScript artifacts. npm's
integrity hashes (`package-lock.json`) cover the package contents. There is no
native binary in the package, so the attack surface is limited to the npm
registry's publishing and delivery path.

Verify the package integrity with:

```bash
npm audit signatures
```

This checks the npm registry signature attestations for every package in your
dependency tree, including `@critiq/cli` and `@critiq/rules`.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3.0 | :x:                |

Security fixes are published as patch releases for the latest minor version
line. Before 1.0.0, breaking changes may ship in minor releases, so we only
maintain the current minor line.

## Vulnerability Disclosure

We follow a coordinated disclosure process:

1. The reporter submits a vulnerability via GitHub private reporting.
2. We acknowledge within 48 hours and begin investigation.
3. We develop and test a fix in a private fork.
4. We publish the fix as a patch release and publish a GitHub Security Advisory.
5. We credit the reporter in the advisory (unless they prefer to remain
   anonymous).

We aim to publish fixes within 30 days of the initial report, and sooner for
critical issues.
