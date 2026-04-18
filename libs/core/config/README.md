# @critiq/core-config

`@critiq/core-config` defines and loads the repository-level Critiq runtime
configuration used by the catalog-first `check` workflow.

## Exports

- `CRITIQ_CONFIG_API_VERSION`
- `CRITIQ_CONFIG_KIND`
- `critiqConfigSchema`
- `normalizeCritiqConfig()`
- `validateCritiqConfig()`
- `loadCritiqConfigText()`
- `loadCritiqConfigFile()`
- `loadCritiqConfigForDirectory()`

## Config file

The current runtime expects `.critiq/config.yaml` with:

```yaml
apiVersion: critiq.dev/v1alpha1
kind: CritiqConfig
catalog:
  package: "@critiq/rules"
preset: recommended
disableRules: []
disableCategories: []
disableLanguages: []
ignorePaths: []
severityOverrides: {}
```

Supported presets:

- `recommended`
- `strict`
- `security`
- `experimental`

`disableCategories` accepts either top-level categories such as `security` or
dot-delimited subcategories such as `security.injection`.

`catalog.package` is optional at the config layer. The OSS CLI and
`@critiq/check-runner` currently default to `@critiq/rules` when it is omitted.
