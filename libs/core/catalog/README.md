# @critiq/core-catalog

`@critiq/core-catalog` defines the rule catalog manifest, resolves catalog
packages, detects repository languages, and filters rules for catalog-first
runtime execution.

## Exports

- `RULE_CATALOG_API_VERSION`
- `RULE_CATALOG_KIND`
- `DEFAULT_RULE_CATALOG_FILENAME`
- `ruleCatalogSchema`
- `validateRuleCatalog()`
- `loadRuleCatalogText()`
- `loadRuleCatalogFile()`
- `resolveCatalogPackage()`
- `resolveCatalogRulePaths()`
- `detectRepositoryLanguages()`
- `filterNormalizedRulesForCatalog()`
