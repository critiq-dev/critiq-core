import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const packageDirectories = [
  'apps/cli',
  'libs/runtime/check-runner',
  'libs/core/finding-schema',
  'libs/core/config',
  'libs/core/catalog',
  'libs/core/rules-dsl',
  'libs/core/diagnostics',
  'libs/core/ir',
  'libs/core/rules-engine',
  'libs/adapters/typescript',
  'tools/testing/harness',
];

const failures = [];

for (const relativeDirectory of packageDirectories) {
  const directoryPath = resolve(workspaceRoot, relativeDirectory);
  const packagePath = resolve(directoryPath, 'package.json');
  const readmePath = resolve(directoryPath, 'README.md');
  const manifest = JSON.parse(readFileSync(packagePath, 'utf8'));

  if (!existsSync(readmePath)) {
    failures.push(`${relativeDirectory}: missing README.md`);
  }

  for (const field of ['name', 'version', 'main', 'types']) {
    if (!manifest[field]) {
      failures.push(`${relativeDirectory}: missing ${field} in package.json`);
    }
  }

  if (relativeDirectory !== 'apps/cli' && !manifest.exports?.['.']) {
    failures.push(`${relativeDirectory}: missing "." export map`);
  }

  if (dirname(packagePath) !== directoryPath) {
    failures.push(`${relativeDirectory}: invalid package path resolution`);
  }
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log(`Verified package metadata and README coverage for ${packageDirectories.length} packages.`);
