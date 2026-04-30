import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const cliManifest = JSON.parse(
  readFileSync(resolve(workspaceRoot, 'apps/cli/package.json'), 'utf8'),
);

const tag = process.argv[2] ?? process.env['GITHUB_REF_NAME'];

if (!tag) {
  console.error('Expected a release tag argument or GITHUB_REF_NAME.');
  process.exit(1);
}

const expectedTag = `v${cliManifest.version}`;

if (tag !== expectedTag) {
  console.error(
    `Release tag mismatch: expected ${expectedTag} for ${cliManifest.name}, received ${tag}.`,
  );
  process.exit(1);
}

console.log(`Verified ${cliManifest.name} version ${cliManifest.version} matches ${tag}.`);
