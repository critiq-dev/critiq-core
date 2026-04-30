import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const rootManifest = JSON.parse(
  readFileSync(resolve(workspaceRoot, 'package.json'), 'utf8'),
);
const changesetsVersion = rootManifest.devDependencies?.['@changesets/cli'];
const baseRef = process.env['GITHUB_BASE_REF']
  ? `origin/${process.env['GITHUB_BASE_REF']}`
  : 'origin/main';

function git(args) {
  return execFileSync('git', args, {
    cwd: workspaceRoot,
    encoding: 'utf8',
  }).trim();
}

const changedFiles = git(['diff', '--name-only', `${baseRef}...HEAD`])
  .split('\n')
  .map((value) => value.trim())
  .filter(Boolean);

const relevantFiles = changedFiles.filter((path) =>
  [
    'apps/cli/',
    'libs/',
    'tools/testing/harness/',
    'package.json',
    'package-lock.json',
    'tsconfig.base.json',
  ].some((prefix) => path === prefix || path.startsWith(prefix)),
);

if (relevantFiles.length === 0) {
  console.log('No public CLI runtime changes detected; skipping changeset enforcement.');
  process.exit(0);
}

const changesetFiles = changedFiles.filter(
  (path) =>
    path.startsWith('.changeset/') &&
    path.endsWith('.md') &&
    path !== '.changeset/README.md',
);

if (changesetFiles.length === 0) {
  console.error(
    [
      'Public CLI runtime changes were detected without a changeset.',
      'Add a changeset before merging this branch.',
      '',
      'Relevant files:',
      ...relevantFiles.map((file) => `- ${file}`),
    ].join('\n'),
  );
  process.exit(1);
}

if (!changesetsVersion) {
  console.error('Expected @changesets/cli to be declared in devDependencies.');
  process.exit(1);
}

execFileSync(
  'npm',
  [
    'exec',
    '--yes',
    `--package=@changesets/cli@${changesetsVersion}`,
    '--',
    'changeset',
    'status',
    '--since',
    baseRef,
  ],
  {
    cwd: workspaceRoot,
    env: {
      ...process.env,
      npm_config_cache:
        process.env['npm_config_cache'] ?? '/tmp/critiq-npm-cache',
    },
    stdio: 'inherit',
  },
);

console.log(
  `Verified changeset coverage for ${relevantFiles.length} public CLI runtime file changes.`,
);
