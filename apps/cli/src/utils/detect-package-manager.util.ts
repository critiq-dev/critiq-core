import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export type PackageManagerId = 'npm' | 'yarn' | 'pnpm' | 'bun';

export interface PackageInstallCommand {
  executable: PackageManagerId;
  args: readonly string[];
  display: string;
}

function readPackageManagerField(cwd: string): PackageManagerId | null {
  const packageJsonPath = join(cwd, 'package.json');

  if (!existsSync(packageJsonPath)) {
    return null;
  }

  try {
    const manifest = JSON.parse(readFileSync(packageJsonPath, 'utf8')) as {
      packageManager?: string;
    };
    const value = manifest.packageManager?.trim();

    if (!value) {
      return null;
    }

    if (value.startsWith('pnpm@')) {
      return 'pnpm';
    }

    if (value.startsWith('yarn@')) {
      return 'yarn';
    }

    if (value.startsWith('npm@')) {
      return 'npm';
    }

    if (value.startsWith('bun@')) {
      return 'bun';
    }
  } catch {
    return null;
  }

  return null;
}

export function detectPackageManager(cwd: string): PackageManagerId {
  const fromField = readPackageManagerField(cwd);

  if (fromField) {
    return fromField;
  }

  if (existsSync(join(cwd, 'bun.lockb')) || existsSync(join(cwd, 'bun.lock'))) {
    return 'bun';
  }

  if (existsSync(join(cwd, 'pnpm-lock.yaml'))) {
    return 'pnpm';
  }

  if (existsSync(join(cwd, 'yarn.lock'))) {
    return 'yarn';
  }

  if (
    existsSync(join(cwd, 'package-lock.json')) ||
    existsSync(join(cwd, 'npm-shrinkwrap.json'))
  ) {
    return 'npm';
  }

  return 'npm';
}

export function buildCatalogInstallCommand(
  packageManager: PackageManagerId,
  packageName: string,
  scope: 'local' | 'global',
): PackageInstallCommand {
  switch (packageManager) {
    case 'yarn':
      if (scope === 'global') {
        return {
          executable: 'yarn',
          args: ['global', 'add', packageName],
          display: `yarn global add ${packageName}`,
        };
      }

      return {
        executable: 'yarn',
        args: ['add', '-D', packageName],
        display: `yarn add -D ${packageName}`,
      };
    case 'pnpm':
      if (scope === 'global') {
        return {
          executable: 'pnpm',
          args: ['add', '-g', packageName],
          display: `pnpm add -g ${packageName}`,
        };
      }

      return {
        executable: 'pnpm',
        args: ['add', '-D', packageName],
        display: `pnpm add -D ${packageName}`,
      };
    case 'bun':
      if (scope === 'global') {
        return {
          executable: 'bun',
          args: ['add', '-g', packageName],
          display: `bun add -g ${packageName}`,
        };
      }

      return {
        executable: 'bun',
        args: ['add', '-d', packageName],
        display: `bun add -d ${packageName}`,
      };
    case 'npm':
      if (scope === 'global') {
        return {
          executable: 'npm',
          args: ['install', '-g', packageName],
          display: `npm install -g ${packageName}`,
        };
      }

      return {
        executable: 'npm',
        args: ['install', '-D', packageName],
        display: `npm install -D ${packageName}`,
      };
  }
}
