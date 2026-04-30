import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const packagePath = resolve(workspaceRoot, 'apps/cli/package.json');
const manifest = JSON.parse(readFileSync(packagePath, 'utf8'));

const failures = [];

if (!manifest.name) {
  failures.push('apps/cli/package.json: missing package name');
}

if (!manifest.exports || !manifest.exports['.']) {
  failures.push('apps/cli/package.json: missing "." export map');
}

if (!manifest.main) {
  failures.push('apps/cli/package.json: missing "main" entry');
}

if (!manifest.types) {
  failures.push('apps/cli/package.json: missing "types" entry');
}

if (manifest.name !== '@critiq/cli') {
  failures.push(
    `apps/cli/package.json: expected package name @critiq/cli, received ${manifest.name}`,
  );
}

if (manifest.publishConfig?.access !== 'public') {
  failures.push(
    'apps/cli/package.json: expected publishConfig.access to be "public"',
  );
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log('Verified export map metadata for @critiq/cli.');
