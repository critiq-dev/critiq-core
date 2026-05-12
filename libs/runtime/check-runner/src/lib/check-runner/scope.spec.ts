import { execFileSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';

import { createDefaultSourceAdapterRegistry } from '../check-runner';
import { filterIgnoredPaths, resolveCheckScope, resolveCheckTarget, resolveSecretsScanScope } from './scope';

function createTempWorkspace(): string {
  return mkdtempSync(join(tmpdir(), 'critiq-scope-'));
}

function writeWorkspaceFile(
  rootDirectory: string,
  relativePath: string,
  content: string,
): void {
  const absolutePath = join(rootDirectory, relativePath);
  mkdirSync(dirname(absolutePath), { recursive: true });
  writeFileSync(absolutePath, content, 'utf8');
}

function runGitCommand(rootDirectory: string, args: string[]): string {
  return execFileSync('git', args, {
    cwd: rootDirectory,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function initializeGitRepository(rootDirectory: string): void {
  runGitCommand(rootDirectory, ['init']);
  runGitCommand(rootDirectory, ['config', 'user.email', 'test@example.com']);
  runGitCommand(rootDirectory, ['config', 'user.name', 'Critiq Test']);
}

function commitAll(rootDirectory: string, message: string): void {
  runGitCommand(rootDirectory, ['add', '-A']);
  runGitCommand(rootDirectory, ['commit', '-m', message, '--no-gpg-sign']);
}

describe('scope resolution', () => {
  let tempDirectory: string;
  let workspaceRoot: string;

  beforeEach(() => {
    tempDirectory = createTempWorkspace();
    workspaceRoot = realpathSync(tempDirectory);
  });

  afterEach(() => {
    rmSync(tempDirectory, { recursive: true, force: true });
  });

  it('uses the git repository root as the display root for nested targets', () => {
    initializeGitRepository(tempDirectory);
    writeWorkspaceFile(
      tempDirectory,
      'packages/api/src/example.ts',
      'export const example = true;\n',
    );

    const result = resolveCheckTarget(tempDirectory, 'packages/api/src/example.ts');

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected nested git target resolution to succeed.');
    }

    expect(relative(workspaceRoot, result.data.absolutePath)).toBe(
      'packages/api/src/example.ts',
    );
    expect(result.data.isDirectory).toBe(false);
    expect(result.data.displayRoot).toBe(workspaceRoot);
    expect(result.data.repoRoot).toBe(workspaceRoot);
  });

  it('uses the immediate scope directory as the display root outside git repositories', () => {
    writeWorkspaceFile(
      tempDirectory,
      'src/example.ts',
      'export const example = true;\n',
    );

    const result = resolveCheckTarget(tempDirectory, 'src/example.ts');

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected plain file target resolution to succeed.');
    }

    expect(relative(workspaceRoot, result.data.absolutePath)).toBe(
      'src/example.ts',
    );
    expect(relative(workspaceRoot, result.data.displayRoot)).toBe('src');
    expect(result.data.repoRoot).toBeUndefined();
  });

  it('parses diff ranges and keeps renamed supported files while skipping deleted and unsupported paths', () => {
    initializeGitRepository(tempDirectory);
    writeWorkspaceFile(
      tempDirectory,
      'src/service.ts',
      [
        'export function transferPayment(accountId: string) {',
        "  return `payment:${accountId}`;",
        '}',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/old-name.ts',
      'export const previousName = true;\n',
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/remove.ts',
      'export const removed = true;\n',
    );
    writeWorkspaceFile(tempDirectory, 'README.md', 'initial\n');
    commitAll(tempDirectory, 'initial');

    runGitCommand(tempDirectory, ['mv', 'src/old-name.ts', 'src/renamed.ts']);
    writeWorkspaceFile(
      tempDirectory,
      'src/renamed.ts',
      [
        'export const renamed = true;',
        'export const marker = "renamed";',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/service.ts',
      [
        'export function transferPayment(accountId: string) {',
        "  return `payment:updated:${accountId}`;",
        '}',
      ].join('\n'),
    );
    rmSync(join(tempDirectory, 'src/remove.ts'));
    writeWorkspaceFile(tempDirectory, 'README.md', 'updated\n');
    commitAll(tempDirectory, 'changes');

    const target = resolveCheckTarget(tempDirectory, '.');

    expect(target.success).toBe(true);

    if (!target.success) {
      throw new Error('Expected repository target resolution to succeed.');
    }

    const result = resolveCheckScope(
      target.data,
      'HEAD~1',
      'HEAD',
      createDefaultSourceAdapterRegistry(),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected diff scope resolution to succeed.');
    }

    expect(result.data.scope).toEqual({
      mode: 'diff',
      base: 'HEAD~1',
      head: 'HEAD',
      changedFileCount: 2,
    });
    expect(result.data.files.map((file) => relative(workspaceRoot, file))).toEqual([
      'src/renamed.ts',
      'src/service.ts',
    ]);
    expect(
      result.data.changedRangesByAbsolutePath.get(
        join(workspaceRoot, 'src/service.ts'),
      ),
    ).toEqual(
      [
        {
          startLine: 2,
          startColumn: 1,
          endLine: 2,
          endColumn: Number.MAX_SAFE_INTEGER,
        },
      ],
    );
    expect(
      result.data.changedRangesByAbsolutePath.get(
        join(workspaceRoot, 'src/renamed.ts'),
      ),
    ).toEqual([
      {
        startLine: 1,
        startColumn: 1,
        endLine: 2,
        endColumn: Number.MAX_SAFE_INTEGER,
      },
    ]);
  });

  it('filters ignored files, dist output, and tests while preserving change ranges for retained files', () => {
    const appPath = join(workspaceRoot, 'src/app.ts');
    const testPath = join(workspaceRoot, 'src/app.test.ts');
    const distPath = join(workspaceRoot, 'dist/generated.ts');
    const customIgnoredPath = join(workspaceRoot, 'src/generated/client.ts');
    const changedRanges = new Map([
      [
        appPath,
        [
          {
            startLine: 1,
            startColumn: 1,
            endLine: 1,
            endColumn: Number.MAX_SAFE_INTEGER,
          },
        ],
      ],
      [testPath, []],
      [distPath, []],
      [customIgnoredPath, []],
    ]);

    const result = filterIgnoredPaths(
      [appPath, testPath, distPath, customIgnoredPath],
      changedRanges,
      workspaceRoot,
      false,
      ['src/generated/**'],
    );

    expect(result.files.map((file) => relative(workspaceRoot, file))).toEqual([
      'src/app.ts',
    ]);
    expect(result.changedRangesByAbsolutePath.get(appPath)).toEqual(
      changedRanges.get(appPath),
    );
    expect(result.changedRangesByAbsolutePath.has(testPath)).toBe(false);
    expect(result.changedRangesByAbsolutePath.has(distPath)).toBe(false);
    expect(result.changedRangesByAbsolutePath.has(customIgnoredPath)).toBe(
      false,
    );
  });

  it('includes changed .env in resolveSecretsScanScope while resolveCheckScope excludes it', () => {
    initializeGitRepository(tempDirectory);
    writeWorkspaceFile(tempDirectory, 'src/app.ts', 'export const x = 1;\n');
    writeWorkspaceFile(tempDirectory, '.env', 'FOO=bar\n');
    commitAll(tempDirectory, 'initial');
    writeWorkspaceFile(
      tempDirectory,
      '.env',
      'FOO=bar\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n',
    );
    writeWorkspaceFile(tempDirectory, 'src/app.ts', 'export const x = 2;\n');
    commitAll(tempDirectory, 'second');

    const target = resolveCheckTarget(tempDirectory, '.');

    expect(target.success).toBe(true);

    if (!target.success) {
      throw new Error('Expected repository target resolution to succeed.');
    }

    const registry = createDefaultSourceAdapterRegistry();
    const checkScope = resolveCheckScope(target.data, 'HEAD~1', 'HEAD', registry);
    const secretsScope = resolveSecretsScanScope(target.data, 'HEAD~1', 'HEAD');

    expect(checkScope.success).toBe(true);
    expect(secretsScope.success).toBe(true);

    if (!checkScope.success || !secretsScope.success) {
      throw new Error('Expected diff scope resolution to succeed.');
    }

    const checkRel = checkScope.data.files
      .map((file) => relative(workspaceRoot, file))
      .sort();
    const secretsRel = secretsScope.data.files
      .map((file) => relative(workspaceRoot, file))
      .sort();

    expect(checkRel).not.toContain('.env');
    const appRel = relative(workspaceRoot, join(workspaceRoot, 'src', 'app.ts'));
    expect(secretsRel).toContain('.env');
    expect(secretsRel).toContain(appRel);
  });
});
