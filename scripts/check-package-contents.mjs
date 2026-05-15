import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const packageDirectory = resolve(workspaceRoot, 'apps/cli');
const packagePath = resolve(packageDirectory, 'package.json');
const readmePath = resolve(packageDirectory, 'README.md');
const manifest = JSON.parse(readFileSync(packagePath, 'utf8'));

const failures = [];

if (!existsSync(readmePath)) {
  failures.push('apps/cli: missing README.md');
}

for (const field of ['name', 'version', 'main', 'types']) {
  if (!manifest[field]) {
    failures.push(`apps/cli: missing ${field} in package.json`);
  }
}

if (!manifest.bin?.critiq) {
  failures.push('apps/cli: missing critiq bin entry');
}

if (manifest.bin?.critiq?.startsWith('./')) {
  failures.push('apps/cli: critiq bin must not use a ./ prefix');
}

if (!manifest.repository?.url) {
  failures.push('apps/cli: missing repository.url in package.json');
}

if (!manifest.description) {
  failures.push('apps/cli: missing description in package.json');
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log('Verified source package metadata and README coverage for @critiq/cli.');
