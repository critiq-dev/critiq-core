import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const schemaFiles = [
  'libs/core/finding-schema/schema/finding-v0.schema.json',
  'libs/core/rules-dsl/schema/rule-document-v0alpha1.schema.json',
];
const before = new Map(
  schemaFiles.map((relativePath) => [
    relativePath,
    readFileSync(resolve(workspaceRoot, relativePath), 'utf8'),
  ]),
);

execFileSync('node', ['libs/core/finding-schema/scripts/generate-finding-v0-schema.cjs'], {
  cwd: workspaceRoot,
  stdio: 'inherit',
});
execFileSync(
  'node',
  ['libs/core/rules-dsl/scripts/generate-rule-document-v0alpha1-schema.cjs'],
  {
    cwd: workspaceRoot,
    stdio: 'inherit',
  },
);

const driftedFiles = schemaFiles.filter(
  (relativePath) =>
    before.get(relativePath) !== readFileSync(resolve(workspaceRoot, relativePath), 'utf8'),
);

if (driftedFiles.length > 0) {
  console.error(`Schema drift detected in:\n${driftedFiles.join('\n')}`);
  process.exit(1);
}

console.log(`Verified schema artifacts for ${schemaFiles.length} packages.`);
