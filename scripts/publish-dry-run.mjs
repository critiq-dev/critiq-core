import { execFileSync, spawnSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const npmCache = process.env.npm_config_cache ?? '/tmp/critiq-npm-cache';
const releasePackageRoot = resolve(workspaceRoot, 'dist/publish/cli');
const fixtureRulesRoot = resolve(
  workspaceRoot,
  'apps/cli/src/test-fixtures/default-rules-package',
);

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: options.cwd ?? workspaceRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      npm_config_cache: npmCache,
      ...(options.env ?? {}),
    },
    stdio: options.stdio ?? 'pipe',
  });
}

function runChecked(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? workspaceRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      npm_config_cache: npmCache,
      ...(options.env ?? {}),
    },
  });

  if (result.status === 0) {
    return result;
  }

  if (result.stdout) {
    process.stdout.write(result.stdout);
  }

  if (result.stderr) {
    process.stderr.write(result.stderr);
  }

  throw new Error(
    `${command} ${args.join(' ')} failed with status ${result.status ?? 'unknown'}.`,
  );
}

console.log('Building @critiq/cli release artifact...');
execFileSync('node', ['scripts/build-release-cli.mjs'], {
  cwd: workspaceRoot,
  stdio: 'inherit',
});

const releaseManifest = JSON.parse(
  readFileSync(resolve(releasePackageRoot, 'package.json'), 'utf8'),
);

if (releaseManifest.bin?.critiq !== 'main.js') {
  throw new Error(
    `Expected published @critiq/cli bin.critiq to be "main.js", found ${JSON.stringify(releaseManifest.bin?.critiq)}.`,
  );
}

if (releaseManifest.repository?.url !== 'git+https://github.com/critiq-dev/critiq-core.git') {
  throw new Error(
    `Expected published @critiq/cli repository.url to match critiq-core provenance, found ${JSON.stringify(releaseManifest.repository?.url)}.`,
  );
}

const internalDependencies = Object.keys(releaseManifest.dependencies ?? {}).filter(
  (dependency) => dependency.startsWith('@critiq/'),
);

if (internalDependencies.length > 0) {
  throw new Error(
    `Expected @critiq/cli to be self-contained. Found internal runtime dependencies: ${internalDependencies.join(', ')}`,
  );
}

const tempRoot = mkdtempSync(resolve(tmpdir(), 'critiq-cli-release-'));

try {
  const cliPackInfo = JSON.parse(
    run('npm', ['pack', '--json', '--pack-destination', tempRoot], {
      cwd: releasePackageRoot,
    }),
  )[0];
  const rulesPackInfo = JSON.parse(
    run('npm', ['pack', '--json', '--pack-destination', tempRoot], {
      cwd: fixtureRulesRoot,
    }),
  )[0];

  const packedFiles = new Set((cliPackInfo.files ?? []).map((file) => file.path));

  for (const expectedPath of [
    'LICENSE',
    'README.md',
    'main.d.ts',
    'main.js',
    'package.json',
    'schema/finding-v0.schema.json',
    'schema/rule-document-v0alpha1.schema.json',
  ]) {
    if (!packedFiles.has(expectedPath)) {
      throw new Error(`Expected packed @critiq/cli artifact to include ${expectedPath}.`);
    }
  }

  const tempProjectRoot = resolve(tempRoot, 'consumer-project');
  mkdirSync(resolve(tempProjectRoot, '.critiq'), { recursive: true });
  mkdirSync(resolve(tempProjectRoot, 'src'), { recursive: true });

  writeFileSync(
    resolve(tempProjectRoot, '.critiq/config.yaml'),
    [
      'apiVersion: critiq.dev/v1alpha1',
      'kind: CritiqConfig',
      'catalog:',
      '  package: "@critiq/rules"',
      'preset: recommended',
      'disableRules: []',
      'disableCategories: []',
      'disableLanguages: []',
      'includeTests: false',
      'ignorePaths: []',
      'severityOverrides: {}',
      '',
    ].join('\n'),
  );
  writeFileSync(
    resolve(tempProjectRoot, 'src/index.ts'),
    "console.log('release dry run');\n",
  );

  runChecked('npm', ['init', '-y'], { cwd: tempProjectRoot });
  runChecked(
    'npm',
    [
      'install',
      '--no-package-lock',
      '--no-save',
      resolve(tempRoot, cliPackInfo.filename),
      resolve(tempRoot, rulesPackInfo.filename),
    ],
    { cwd: tempProjectRoot },
  );

  const helpResult = runChecked(
    'node',
    ['node_modules/@critiq/cli/main.js', '--help'],
    { cwd: tempProjectRoot },
  );

  if (!helpResult.stdout.includes('critiq check')) {
    throw new Error('Expected @critiq/cli --help output to mention `critiq check`.');
  }

  const checkResult = spawnSync(
    'node',
    ['node_modules/@critiq/cli/main.js', 'check', '.', '--format', 'json'],
    {
      cwd: tempProjectRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        npm_config_cache: npmCache,
      },
    },
  );

  if (checkResult.status !== 1) {
    if (checkResult.stdout) {
      process.stdout.write(checkResult.stdout);
    }

    if (checkResult.stderr) {
      process.stderr.write(checkResult.stderr);
    }

    throw new Error(
      `Expected packaged @critiq/cli check smoke to exit with 1, received ${checkResult.status}.`,
    );
  }

  const envelope = JSON.parse(checkResult.stdout.trim());

  if (envelope.command !== 'check' || envelope.findingCount < 1) {
    throw new Error(
      'Expected packaged @critiq/cli check smoke to return a finding-producing check envelope.',
    );
  }

  console.log('Validated @critiq/cli pack contents and clean-install smoke behavior.');
} finally {
  rmSync(tempRoot, { recursive: true, force: true });
}
