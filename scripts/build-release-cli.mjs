import { build } from 'esbuild';
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { resolve } from 'node:path';

const workspaceRoot = resolve(import.meta.dirname, '..');
const outputDirectory = resolve(workspaceRoot, 'dist/publish/cli');
const schemaOutputDirectory = resolve(outputDirectory, 'schema');
const rootPackageJsonPath = resolve(workspaceRoot, 'package.json');
const cliPackageJsonPath = resolve(workspaceRoot, 'apps/cli/package.json');

const rootManifest = JSON.parse(readFileSync(rootPackageJsonPath, 'utf8'));
const cliManifest = JSON.parse(readFileSync(cliPackageJsonPath, 'utf8'));
const externalDependencies = Object.keys(cliManifest.dependencies ?? {}).sort();

rmSync(outputDirectory, { recursive: true, force: true });
mkdirSync(schemaOutputDirectory, { recursive: true });

await build({
  absWorkingDir: workspaceRoot,
  bundle: true,
  entryPoints: ['apps/cli/src/main.ts'],
  external: externalDependencies,
  format: 'cjs',
  legalComments: 'none',
  outfile: resolve(outputDirectory, 'main.js'),
  platform: 'node',
  sourcemap: false,
  target: ['node20'],
  tsconfig: resolve(workspaceRoot, 'tsconfig.base.json'),
});

chmodSync(resolve(outputDirectory, 'main.js'), 0o755);

for (const [source, target] of [
  ['apps/cli/main.d.ts', 'main.d.ts'],
  ['apps/cli/README.md', 'README.md'],
  ['LICENSE', 'LICENSE'],
  [
    'libs/core/finding-schema/schema/finding-v0.schema.json',
    'schema/finding-v0.schema.json',
  ],
  [
    'libs/core/rules-dsl/schema/rule-document-v0alpha1.schema.json',
    'schema/rule-document-v0alpha1.schema.json',
  ],
]) {
  copyFileSync(resolve(workspaceRoot, source), resolve(outputDirectory, target));
}

const publishManifest = {
  name: cliManifest.name,
  version: cliManifest.version,
  private: false,
  description: cliManifest.description,
  license: rootManifest.license,
  type: cliManifest.type,
  bin: cliManifest.bin,
  main: cliManifest.main,
  types: cliManifest.types,
  exports: cliManifest.exports,
  engines: rootManifest.engines,
  publishConfig: cliManifest.publishConfig,
  files: ['LICENSE', 'README.md', 'main.d.ts', 'main.js', 'schema'],
  dependencies: cliManifest.dependencies,
};

writeFileSync(
  resolve(outputDirectory, 'package.json'),
  `${JSON.stringify(publishManifest, null, 2)}\n`,
);

console.log(`Built @critiq/cli release artifact at ${outputDirectory}.`);
