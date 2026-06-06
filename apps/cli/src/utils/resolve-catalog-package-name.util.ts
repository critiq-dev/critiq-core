import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { loadCritiqConfigForDirectory } from '@critiq/core-config';
import { DEFAULT_CATALOG_PACKAGE_NAME } from '@critiq/check-runner';

export function resolveCatalogPackageNameForEnsure(
  cwd: string,
): string | null {
  const loaded = loadCritiqConfigForDirectory(cwd);

  if (!loaded.success) {
    const firstCode = (
      loaded as Extract<typeof loaded, { success: false }>
    ).diagnostics[0]?.code;

    if (firstCode === 'config.file.not-found') {
      return DEFAULT_CATALOG_PACKAGE_NAME;
    }

    return null;
  }

  return loaded.data.catalogPackage ?? DEFAULT_CATALOG_PACKAGE_NAME;
}

export function repoHasPackageJson(cwd: string): boolean {
  return existsSync(join(cwd, 'package.json'));
}

export function canInstallCatalogLocally(cwd: string): boolean {
  return repoHasPackageJson(cwd);
}

export function isDefaultInstallableCatalogPackage(
  packageName: string,
): boolean {
  return packageName === DEFAULT_CATALOG_PACKAGE_NAME;
}
