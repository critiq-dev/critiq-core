# Internal GitHub Packages setup

`critiq-core` publishes 18 internal libraries to GitHub Packages as `@critiq-dev/*`.
Only `critiq-pro` should consume these packages today.

## One-time org configuration

1. Confirm the `critiq-dev` org plan supports **private** GitHub Packages linked to the public `critiq-core` repository.
2. Merge and run [`.github/workflows/publish-internal-packages.yml`](../.github/workflows/publish-internal-packages.yml) on `main` (or trigger `workflow_dispatch`) to create the first package versions.
3. For each published package under **GitHub → Packages**:
   - Set visibility to **Private**
   - Under **Manage Actions access** / repository access, grant **Read** to `critiq-dev/critiq-pro` only
   - Do not grant org-wide read unless another repo needs access

## Package list

All packages share lockstep versions and an `internal` dist-tag:

- `@critiq-dev/core-diagnostics`
- `@critiq-dev/core-finding-schema`
- `@critiq-dev/util-yaml-loader`
- `@critiq-dev/core-rules-dsl`
- `@critiq-dev/core-ir`
- `@critiq-dev/core-config`
- `@critiq-dev/core-rules-engine`
- `@critiq-dev/adapter-shared`
- `@critiq-dev/adapter-go`
- `@critiq-dev/adapter-java`
- `@critiq-dev/adapter-php`
- `@critiq-dev/adapter-python`
- `@critiq-dev/adapter-ruby`
- `@critiq-dev/adapter-rust`
- `@critiq-dev/adapter-typescript`
- `@critiq-dev/core-catalog`
- `@critiq-dev/check-runner`
- `@critiq-dev/testing-harness`

## Local publish verification

```bash
npm run build
npm run publish:internal:dry-run
```

Publishing requires a token with `write:packages` and `NODE_AUTH_TOKEN` set.

## Relationship to public releases

| Workflow | Registry | Packages |
| --- | --- | --- |
| `release.yml` | `registry.npmjs.org` | `@critiq/cli` only |
| `publish-internal-packages.yml` | `npm.pkg.github.com` | `@critiq-dev/*` internal libs |

Public OSS releases are unchanged. Internal libs stay off npmjs.org.
