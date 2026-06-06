import { resolveCatalogPackage } from '@critiq/core-catalog';

import {
  getGlobalNodeModulesRoots,
  getRepoNodeModulesRoot,
} from './node-modules-roots.util';

export type CatalogPackageLocation = 'repo' | 'global';

export interface ResolvedCatalogPackageProbe {
  packageName: string;
  location: CatalogPackageLocation;
  packageRoot: string;
}

function probeFromBasePath(
  cwd: string,
  packageName: string,
  basePath: string,
): string | null {
  const result = resolveCatalogPackage(cwd, packageName, [basePath]);

  if (!result.success) {
    return null;
  }

  return result.data.packageRoot;
}

export function probeCatalogPackageInRepo(
  cwd: string,
  packageName: string,
): string | null {
  return probeFromBasePath(cwd, packageName, getRepoNodeModulesRoot(cwd));
}

export function probeCatalogPackageGlobally(
  cwd: string,
  packageName: string,
): string | null {
  for (const globalRoot of getGlobalNodeModulesRoots()) {
    const packageRoot = probeFromBasePath(cwd, packageName, globalRoot);

    if (packageRoot) {
      return packageRoot;
    }
  }

  return null;
}

export function probeCatalogPackageResolution(
  cwd: string,
  packageName: string,
  options: {
    includeGlobal?: boolean;
  } = {},
): ResolvedCatalogPackageProbe | null {
  const repoPackageRoot = probeCatalogPackageInRepo(cwd, packageName);

  if (repoPackageRoot) {
    return {
      packageName,
      location: 'repo',
      packageRoot: repoPackageRoot,
    };
  }

  if (options.includeGlobal !== false) {
    const globalPackageRoot = probeCatalogPackageGlobally(cwd, packageName);

    if (globalPackageRoot) {
      return {
        packageName,
        location: 'global',
        packageRoot: globalPackageRoot,
      };
    }
  }

  return null;
}
