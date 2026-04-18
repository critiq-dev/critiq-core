import { resolve } from 'node:path';

/**
 * Resolves an absolute workspace path from a known root directory.
 */
export function resolveWorkspacePath(
  rootDirectory: string,
  ...segments: readonly string[]
): string {
  return resolve(rootDirectory, ...segments);
}
