import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

function tryCommandOutput(command: string, args: readonly string[]): string | null {
  try {
    return execFileSync(command, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return null;
  }
}

export function getRepoNodeModulesRoot(cwd: string): string {
  return resolve(cwd, 'node_modules');
}

export function getGlobalNodeModulesRoots(): string[] {
  const roots = new Set<string>();

  const npmRoot = tryCommandOutput('npm', ['root', '-g']);

  if (npmRoot) {
    roots.add(npmRoot);
  }

  const pnpmRoot = tryCommandOutput('pnpm', ['root', '-g']);

  if (pnpmRoot) {
    roots.add(pnpmRoot);
  }

  const yarnGlobalDir = tryCommandOutput('yarn', ['global', 'dir']);

  if (yarnGlobalDir) {
    roots.add(resolve(yarnGlobalDir, 'node_modules'));
  }

  return [...roots].filter((root) => existsSync(root));
}
