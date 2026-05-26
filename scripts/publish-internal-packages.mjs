import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { basename, resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const manifestPath = resolve(import.meta.dirname, 'internal-packages.manifest.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const stagingRoot = resolve(workspaceRoot, 'dist/publish/internal');
const rootManifest = JSON.parse(
  readFileSync(resolve(workspaceRoot, 'package.json'), 'utf8'),
);

const args = process.argv.slice(2);
const dryRun = args.includes('--dry-run');
const publish = args.includes('--publish');
const versionFlagIndex = args.indexOf('--version');
const version =
  versionFlagIndex >= 0 ? args[versionFlagIndex + 1]?.trim() : undefined;
const distTagFlagIndex = args.indexOf('--dist-tag');
const distTag =
  distTagFlagIndex >= 0 ? args[distTagFlagIndex + 1]?.trim() : 'internal';

if (!dryRun && !publish) {
  console.error('Expected --dry-run or --publish.');
  process.exit(1);
}

if (publish && !version) {
  console.error('Expected --version when using --publish.');
  process.exit(1);
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function rewriteScopedName(name) {
  if (typeof name !== 'string') {
    return name;
  }

  if (name.startsWith(`${manifest.sourceScope}/`)) {
    return name.replace(
      `${manifest.sourceScope}/`,
      `${manifest.scope}/`,
    );
  }

  return name;
}

function rewriteDependencyVersions(dependencies) {
  if (!dependencies) {
    return dependencies;
  }

  return Object.fromEntries(
    Object.entries(dependencies).map(([name, value]) => {
      const rewrittenName = rewriteScopedName(name);

      if (
        typeof value === 'string' &&
        rewrittenName.startsWith(`${manifest.scope}/`)
      ) {
        return [rewrittenName, version ?? value];
      }

      return [rewrittenName, value];
    }),
  );
}

function stagePackage(entry) {
  const sourceDirectory = resolve(workspaceRoot, entry.distPath);
  const packageJsonPath = resolve(sourceDirectory, 'package.json');

  if (!existsSync(packageJsonPath)) {
    fail(`Missing built package at ${sourceDirectory}. Run npm run build first.`);
  }

  const sourceManifest = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
  const outputDirectory = resolve(stagingRoot, entry.publishName);

  rmSync(outputDirectory, { recursive: true, force: true });
  cpSync(sourceDirectory, outputDirectory, { recursive: true });

  const publishManifest = {
    ...sourceManifest,
    name: `${manifest.scope}/${entry.publishName}`,
    version: version ?? sourceManifest.version,
    private: false,
    dependencies: rewriteDependencyVersions(sourceManifest.dependencies),
    peerDependencies: rewriteDependencyVersions(sourceManifest.peerDependencies),
    optionalDependencies: rewriteDependencyVersions(
      sourceManifest.optionalDependencies,
    ),
    publishConfig: {
      registry: 'https://npm.pkg.github.com',
      access: 'restricted',
    },
    repository: {
      type: 'git',
      url: 'git+https://github.com/critiq-dev/critiq-core.git',
    },
    license: rootManifest.license,
    engines: rootManifest.engines,
  };

  delete publishManifest.devDependencies;

  writeFileSync(
    resolve(outputDirectory, 'package.json'),
    `${JSON.stringify(publishManifest, null, 2)}\n`,
  );

  return {
    name: publishManifest.name,
    version: publishManifest.version,
    directory: outputDirectory,
  };
}

rmSync(stagingRoot, { recursive: true, force: true });

const stagedPackages = manifest.packages.map(stagePackage);

console.log(
  `${dryRun ? 'Staged' : 'Prepared'} ${stagedPackages.length} internal packages at ${stagingRoot}.`,
);

for (const pkg of stagedPackages) {
  console.log(`- ${pkg.name}@${pkg.version} (${basename(pkg.directory)})`);
}

if (dryRun) {
  process.exit(0);
}

for (const pkg of stagedPackages) {
  const publishResult = spawnSync(
    'npm',
    ['publish', pkg.directory, '--registry', 'https://npm.pkg.github.com'],
    {
      cwd: workspaceRoot,
      stdio: 'inherit',
      env: process.env,
    },
  );

  if (publishResult.status !== 0) {
    process.exit(publishResult.status ?? 1);
  }

  const tagResult = spawnSync(
    'npm',
    [
      'dist-tag',
      'add',
      `${pkg.name}@${pkg.version}`,
      distTag,
      '--registry',
      'https://npm.pkg.github.com',
    ],
    {
      cwd: workspaceRoot,
      stdio: 'inherit',
      env: process.env,
    },
  );

  if (tagResult.status !== 0) {
    process.exit(tagResult.status ?? 1);
  }
}

console.log(
  `Published ${stagedPackages.length} packages at version ${version} with dist-tag "${distTag}".`,
);
