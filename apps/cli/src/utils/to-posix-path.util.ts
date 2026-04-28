import { sep } from 'node:path';

export function toPosixPath(value: string): string {
  return value.split(sep).join('/');
}
