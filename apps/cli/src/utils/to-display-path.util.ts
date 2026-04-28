import { isAbsolute, relative } from 'node:path';

import { toPosixPath } from './to-posix-path.util';

export function toDisplayPath(cwd: string, absolutePath: string): string {
  const relativePath = toPosixPath(relative(cwd, absolutePath));

  if (
    relativePath.length > 0 &&
    !relativePath.startsWith('..') &&
    !isAbsolute(relativePath)
  ) {
    return relativePath;
  }

  return toPosixPath(absolutePath);
}
