import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const packageDirectories = [
  'apps/cli',
  'libs/runtime/check-runner',
  'libs/core/finding-schema',
  'libs/core/rules-dsl',
  'libs/core/diagnostics',
  'libs/core/ir',
  'libs/core/rules-engine',
  'libs/adapters/typescript',
  'tools/testing/harness',
];

for (const relativeDirectory of packageDirectories) {
  console.log(`Packing ${relativeDirectory}...`);
  execFileSync('npm', ['pack', '--dry-run', '--cache', '/tmp/critiq-npm-cache'], {
    cwd: resolve(workspaceRoot, relativeDirectory),
    env: {
      ...process.env,
      npm_config_cache: process.env.npm_config_cache ?? '/tmp/critiq-npm-cache',
    },
    stdio: 'inherit',
  });
}

console.log(`Completed publish dry-run for ${packageDirectories.length} packages.`);
