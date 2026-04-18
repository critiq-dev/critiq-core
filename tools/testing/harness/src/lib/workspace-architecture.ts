import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const rootScripts = ['lint', 'test', 'build', 'typecheck', 'verify'] as const;
const expectedProjects = [
  {
    name: 'cli',
    projectType: 'application',
    root: 'apps/cli',
    tags: ['scope:oss-core', 'type:app'],
  },
  {
    name: 'check-runner',
    projectType: 'library',
    root: 'libs/runtime/check-runner',
    tags: ['scope:oss-core', 'type:runtime'],
  },
  {
    name: 'finding-schema',
    projectType: 'library',
    root: 'libs/core/finding-schema',
    tags: ['scope:oss-core', 'type:core'],
  },
  {
    name: 'config',
    projectType: 'library',
    root: 'libs/core/config',
    tags: ['scope:oss-core', 'type:core'],
  },
  {
    name: 'catalog',
    projectType: 'library',
    root: 'libs/core/catalog',
    tags: ['scope:oss-core', 'type:core'],
  },
  {
    name: 'rules-dsl',
    projectType: 'library',
    root: 'libs/core/rules-dsl',
    tags: ['scope:oss-core', 'type:core'],
  },
  {
    name: 'diagnostics',
    projectType: 'library',
    root: 'libs/core/diagnostics',
    tags: ['scope:oss-core', 'type:core'],
  },
  {
    name: 'rules-engine',
    projectType: 'library',
    root: 'libs/core/rules-engine',
    tags: ['scope:oss-core', 'type:core'],
  },
  {
    name: 'ir',
    projectType: 'library',
    root: 'libs/core/ir',
    tags: ['scope:oss-core', 'type:core'],
  },
  {
    name: 'typescript',
    projectType: 'library',
    root: 'libs/adapters/typescript',
    tags: ['scope:oss-core', 'type:adapter'],
  },
  {
    name: 'file-system',
    projectType: 'library',
    root: 'libs/utils/file-system',
    tags: ['scope:oss-core', 'type:util'],
  },
  {
    name: 'yaml-loader',
    projectType: 'library',
    root: 'libs/utils/yaml-loader',
    tags: ['scope:oss-core', 'type:util'],
  },
  {
    name: 'harness',
    projectType: 'library',
    root: 'tools/testing/harness',
    tags: ['scope:oss-core', 'type:test'],
  },
] as const;
const expectedRootScripts = {
  build: 'nx run-many -t build --all',
  lint: 'nx run-many -t lint --all',
  test: 'nx run-many -t test --all',
  typecheck: 'nx run-many -t typecheck --all',
  verify: 'npm run lint && npm run test && npm run build && npm run typecheck',
} as const;
const expectedDepConstraints = [
  { sourceTag: 'type:util', onlyDependOnLibsWithTags: ['type:util'] },
  {
    sourceTag: 'type:core',
    onlyDependOnLibsWithTags: ['type:core', 'type:util'],
  },
  {
    sourceTag: 'type:adapter',
    onlyDependOnLibsWithTags: ['type:core', 'type:util'],
  },
  {
    sourceTag: 'type:runtime',
    onlyDependOnLibsWithTags: ['type:adapter', 'type:core', 'type:util'],
  },
  {
    sourceTag: 'type:test',
    onlyDependOnLibsWithTags: [
      'type:adapter',
      'type:core',
      'type:runtime',
      'type:util',
    ],
  },
  {
    sourceTag: 'type:app',
    onlyDependOnLibsWithTags: [
      'type:adapter',
      'type:core',
      'type:runtime',
      'type:test',
      'type:util',
    ],
  },
] as const;

/**
 * Describes the small slice of project metadata that CRQ-OSS-01 locks down.
 */
export interface WorkspaceProjectDefinition {
  name: string;
  projectType: string;
  root: string;
  tags: readonly string[];
}

/**
 * Describes a single module-boundary dependency rule from the root ESLint config.
 */
export interface WorkspaceDepConstraint {
  sourceTag: string;
  onlyDependOnLibsWithTags: readonly string[];
}

/**
 * Captures the repo-level architecture contract that this story establishes.
 */
export interface WorkspaceArchitectureSnapshot {
  projects: WorkspaceProjectDefinition[];
  rootScripts: Partial<Record<(typeof rootScripts)[number], string>>;
  depConstraints: WorkspaceDepConstraint[];
}

async function readJsonFile<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

function sortStrings(values: readonly string[]): string[] {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function normalizeDepConstraints(
  constraints: readonly WorkspaceDepConstraint[],
): WorkspaceDepConstraint[] {
  return constraints
    .map((constraint) => ({
      sourceTag: constraint.sourceTag,
      onlyDependOnLibsWithTags: sortStrings(
        constraint.onlyDependOnLibsWithTags,
      ),
    }))
    .sort((left, right) => left.sourceTag.localeCompare(right.sourceTag));
}

async function readDepConstraints(
  repoRoot: string,
): Promise<WorkspaceDepConstraint[]> {
  const eslintConfigPath = resolve(repoRoot, 'eslint.config.mjs');
  const eslintConfigSource = await readFile(eslintConfigPath, 'utf8');
  const constraintBlocks = [
    ...eslintConfigSource.matchAll(
      /\{\s*sourceTag:\s*['"]([^'"]+)['"],\s*onlyDependOnLibsWithTags:\s*\[([\s\S]*?)\],\s*\}/g,
    ),
  ];

  return constraintBlocks.map((match) => ({
    sourceTag: match[1],
    onlyDependOnLibsWithTags: [...match[2].matchAll(/['"]([^'"]+)['"]/g)].map(
      ([, value]) => value,
    ),
  }));
}

/**
 * Reads the workspace config that CRQ-OSS-01 is expected to lock down.
 */
export async function readWorkspaceArchitecture(
  repoRoot = resolve(__dirname, '../../../../../'),
): Promise<WorkspaceArchitectureSnapshot> {
  const packageJson = await readJsonFile<{
    scripts?: Partial<Record<(typeof rootScripts)[number], string>>;
  }>(resolve(repoRoot, 'package.json'));

  const projects = await Promise.all(
    expectedProjects.map(async ({ root }) => {
      const projectJson = await readJsonFile<{
        name: string;
        projectType: string;
        tags?: string[];
      }>(resolve(repoRoot, root, 'project.json'));

      return {
        name: projectJson.name,
        projectType: projectJson.projectType,
        root,
        tags: projectJson.tags ?? [],
      };
    }),
  );

  return {
    projects,
    rootScripts: packageJson.scripts ?? {},
    depConstraints: await readDepConstraints(repoRoot),
  };
}

/**
 * Validates the project tags, root scripts, and boundary matrix required by CRQ-OSS-01.
 */
export function validateWorkspaceArchitecture(
  snapshot: WorkspaceArchitectureSnapshot,
): string[] {
  const issues: string[] = [];

  for (const scriptName of rootScripts) {
    if (!snapshot.rootScripts[scriptName]) {
      issues.push(`Missing root script: ${scriptName}`);
      continue;
    }

    if (snapshot.rootScripts[scriptName] !== expectedRootScripts[scriptName]) {
      issues.push(
        `Root script ${scriptName} does not match the expected command.`,
      );
    }
  }

  for (const expectedProject of expectedProjects) {
    const actualProject = snapshot.projects.find(
      (project) => project.root === expectedProject.root,
    );

    if (!actualProject) {
      issues.push(`Missing project at ${expectedProject.root}.`);
      continue;
    }

    if (actualProject.name !== expectedProject.name) {
      issues.push(
        `Project ${expectedProject.root} should be named ${expectedProject.name}, received ${actualProject.name}.`,
      );
    }

    if (actualProject.projectType !== expectedProject.projectType) {
      issues.push(
        `Project ${expectedProject.root} should be a ${expectedProject.projectType}, received ${actualProject.projectType}.`,
      );
    }

    for (const tag of expectedProject.tags) {
      if (!actualProject.tags.includes(tag)) {
        issues.push(
          `Project ${expectedProject.root} is missing required tag ${tag}.`,
        );
      }
    }
  }

  const appProjects = snapshot.projects.filter((project) =>
    project.tags.includes('type:app'),
  );

  if (appProjects.length !== 1 || appProjects[0]?.root !== 'apps/cli') {
    issues.push('Expected exactly one type:app project rooted at apps/cli.');
  }

  if (
    JSON.stringify(normalizeDepConstraints(snapshot.depConstraints)) !==
    JSON.stringify(normalizeDepConstraints(expectedDepConstraints))
  ) {
    issues.push(
      'Module boundaries are not configured with the expected dependency matrix.',
    );
  }

  return issues;
}
