import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const publishablePackages = [
  'apps/cli/package.json',
  'libs/runtime/check-runner/package.json',
  'libs/core/finding-schema/package.json',
  'libs/core/config/package.json',
  'libs/core/catalog/package.json',
  'libs/core/rules-dsl/package.json',
  'libs/core/diagnostics/package.json',
  'libs/core/ir/package.json',
  'libs/core/rules-engine/package.json',
  'libs/adapters/typescript/package.json',
  'tools/testing/harness/package.json',
];

const failures = [];

for (const relativePath of publishablePackages) {
  const packagePath = resolve(workspaceRoot, relativePath);
  const manifest = JSON.parse(readFileSync(packagePath, 'utf8'));

  if (!manifest.name) {
    failures.push(`${relativePath}: missing package name`);
  }

  if (!manifest.exports || !manifest.exports['.']) {
    failures.push(`${relativePath}: missing "." export map`);
  }

  if (!manifest.main) {
    failures.push(`${relativePath}: missing "main" entry`);
  }

  if (!manifest.types) {
    failures.push(`${relativePath}: missing "types" entry`);
  }
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log(`Verified export maps for ${publishablePackages.length} package manifests.`);
