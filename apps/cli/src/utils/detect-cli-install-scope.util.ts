import { existsSync, realpathSync } from 'node:fs';
import { resolve, sep } from 'node:path';

import { getGlobalNodeModulesRoots, getRepoNodeModulesRoot } from './node-modules-roots.util';

export type CliInstallScope = 'local' | 'global' | 'external';

function safeRealpath(path: string): string | null {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
}

function normalizeEntryPath(entryPath: string | undefined): string | null {
  if (!entryPath) {
    return null;
  }

  return safeRealpath(entryPath) ?? resolve(entryPath);
}

export function detectCliInstallScope(
  cwd: string,
  entryPath = process.argv[1],
): CliInstallScope {
  const resolvedEntryPath = normalizeEntryPath(entryPath);

  if (!resolvedEntryPath) {
    return 'external';
  }

  const repoNodeModules = safeRealpath(getRepoNodeModulesRoot(cwd));

  if (repoNodeModules) {
    const localCliMain = safeRealpath(
      resolve(repoNodeModules, '@critiq/cli/main.js'),
    );
    const localBin = safeRealpath(resolve(repoNodeModules, '.bin/critiq'));

    if (
      resolvedEntryPath === localCliMain ||
      resolvedEntryPath === localBin ||
      resolvedEntryPath.startsWith(`${resolve(repoNodeModules, '@critiq/cli')}${sep}`)
    ) {
      return 'local';
    }
  }

  for (const globalRoot of getGlobalNodeModulesRoots()) {
    const globalCliMain = resolve(globalRoot, '@critiq/cli/main.js');
    const globalBin = resolve(globalRoot, '.bin/critiq');

    if (
      resolvedEntryPath === safeRealpath(globalCliMain) ||
      resolvedEntryPath === safeRealpath(globalBin) ||
      resolvedEntryPath.startsWith(`${resolve(globalRoot, '@critiq/cli')}${sep}`)
    ) {
      return 'global';
    }
  }

  if (resolvedEntryPath.includes(`${sep}node_modules${sep}`)) {
    return 'external';
  }

  if (existsSync(resolvedEntryPath)) {
    return 'external';
  }

  return 'external';
}
