import { minimatch } from 'minimatch';
import { execFileSync } from 'node:child_process';
import { realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve } from 'node:path';

import type { Diagnostic } from '@critiq/core-diagnostics';
import type { DiffRange } from '@critiq/core-rules-engine';

import {
  createCheckRuntimeDiagnostic,
  createCliInputDiagnostic,
  hasGlobMagic,
  toDisplayPath,
  toPosixPath,
  walkFiles,
  type CheckResolvedScope,
  type CheckResolvedTarget,
  type SourceAdapterRegistry,
} from './shared';

const defaultIgnoredTestPatterns = [
  '**/__tests__/**',
  '**/spec/**',
  '**/src/test/**',
  '**/test/**',
  '**/tests/**',
  '**/*.spec.js',
  '**/*.spec.jsx',
  '**/*.spec.java',
  '**/*.spec.php',
  '**/*.spec.rb',
  '**/*.spec.rs',
  '**/*.spec.ts',
  '**/*.spec.tsx',
  '**/*Spec.java',
  '**/*Test.java',
  '**/*Test.php',
  '**/*Tests.java',
  '**/*_spec.rb',
  '**/*_test.go',
  '**/*_test.py',
  '**/*_test.rb',
  '**/*_test.rs',
  '**/*.test.js',
  '**/*.test.jsx',
  '**/*.test.py',
  '**/*.test.rs',
  '**/*.test.ts',
  '**/*.test.tsx',
  '**/test_*.py',
] as const;

const defaultIgnoredPathPatterns = [
  '**/.nx/**',
  '**/.serverless/**',
  '**/.yarn/cache/**',
  '**/cdk.out/**',
  '**/coverage/**',
  '**/dist/**',
  '**/node_modules/**',
  '**/vendor/**',
  '**/*.d.ts',
  '**/*.generated.go',
  '**/*.generated.py',
  '**/*.generated.js',
  '**/*.generated.ts',
  '**/*_generated.go',
] as const;

function isPathWithinDirectory(
  directoryPath: string,
  candidatePath: string,
): boolean {
  const relativePath = relative(directoryPath, candidatePath);

  return (
    relativePath.length === 0 ||
    (!relativePath.startsWith('..') && !isAbsolute(relativePath))
  );
}

function tryResolveGitRepoRoot(workingDirectory: string): string | undefined {
  try {
    return toPosixPath(
      execFileSync('git', ['rev-parse', '--show-toplevel'], {
        cwd: workingDirectory,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim(),
    );
  } catch {
    return undefined;
  }
}

export function resolveCheckTarget(
  cwd: string,
  target: string | undefined,
):
  | { success: true; data: CheckResolvedTarget }
  | { success: false; diagnostics: Diagnostic[] } {
  const resolvedTarget = target ?? '.';

  if (hasGlobMagic(resolvedTarget)) {
    return {
      success: false,
      diagnostics: [
        createCliInputDiagnostic(
          `Expected a concrete path for \`${resolvedTarget}\`, not a glob.`,
        ),
      ],
    };
  }

  const candidatePath = resolve(cwd, resolvedTarget);

  try {
    const absolutePath = toPosixPath(realpathSync(candidatePath));
    const stats = statSync(absolutePath);

    if (!stats.isDirectory() && !stats.isFile()) {
      return {
        success: false,
        diagnostics: [
          createCliInputDiagnostic(
            `Expected \`${resolvedTarget}\` to be a file or directory.`,
          ),
        ],
      };
    }

    const scopeDirectory = stats.isDirectory()
      ? absolutePath
      : dirname(absolutePath);
    const repoRoot = tryResolveGitRepoRoot(scopeDirectory);

    return {
      success: true,
      data: {
        absolutePath,
        isDirectory: stats.isDirectory(),
        displayRoot: repoRoot ?? scopeDirectory,
        repoRoot,
      },
    };
  } catch {
    return {
      success: false,
      diagnostics: [
        {
          ...createCliInputDiagnostic(`No files matched \`${resolvedTarget}\`.`),
          details: {
            target: resolvedTarget,
          },
        },
      ],
    };
  }
}

function parseChangedRange(
  startLineText: string,
  countText: string | undefined,
): DiffRange | null {
  const startLine = Number.parseInt(startLineText, 10);
  const count = countText ? Number.parseInt(countText, 10) : 1;

  if (!Number.isInteger(startLine) || !Number.isInteger(count) || count <= 0) {
    return null;
  }

  return {
    startLine,
    startColumn: 1,
    endLine: startLine + count - 1,
    endColumn: Number.MAX_SAFE_INTEGER,
  };
}

function normalizeGitDiffPath(value: string): string | null {
  if (value === '/dev/null') {
    return null;
  }

  if (value.startsWith('b/')) {
    return value.slice(2);
  }

  return value;
}

function parseGitDiffChangedRanges(output: string): Map<string, DiffRange[]> {
  const changedRanges = new Map<string, DiffRange[]>();
  let currentPath: string | null = null;

  for (const line of output.split(/\r?\n/)) {
    if (line.startsWith('+++ ')) {
      currentPath = normalizeGitDiffPath(line.slice(4));

      if (currentPath && !changedRanges.has(currentPath)) {
        changedRanges.set(currentPath, []);
      }

      continue;
    }

    if (!currentPath || !line.startsWith('@@ ')) {
      continue;
    }

    const match = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);

    if (!match) {
      continue;
    }

    const changedRange = parseChangedRange(match[1], match[2]);

    if (!changedRange) {
      continue;
    }

    changedRanges.set(currentPath, [
      ...(changedRanges.get(currentPath) ?? []),
      changedRange,
    ]);
  }

  return changedRanges;
}

function runGitCommand(
  cwd: string,
  args: string[],
):
  | { success: true; stdout: string }
  | { success: false; diagnostics: Diagnostic[] } {
  try {
    return {
      success: true,
      stdout: execFileSync('git', args, {
        cwd,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    };
  } catch (error) {
    return {
      success: false,
      diagnostics: [
        createCheckRuntimeDiagnostic(
          'cli.git.command.failed',
          error instanceof Error
            ? error.message
            : 'Unexpected git command failure.',
          {
            args,
          },
        ),
      ],
    };
  }
}

export function resolveCheckScope(
  target: CheckResolvedTarget,
  baseRef: string | undefined,
  headRef: string | undefined,
  registry: SourceAdapterRegistry,
):
  | { success: true; data: CheckResolvedScope }
  | { success: false; diagnostics: Diagnostic[] } {
  if ((baseRef && !headRef) || (!baseRef && headRef)) {
    return {
      success: false,
      diagnostics: [
        createCheckRuntimeDiagnostic(
          'cli.argument.invalid',
          'Expected `--base` and `--head` to be provided together.',
        ),
      ],
    };
  }

  if (!baseRef && !headRef) {
    const files = target.isDirectory
      ? walkFiles(target.absolutePath)
      : [target.absolutePath];

    return {
      success: true,
      data: {
        scope: {
          mode: 'repo',
        },
        files,
        changedRangesByAbsolutePath: new Map<string, DiffRange[]>(),
      },
    };
  }

  const diffScope = resolveRepositoryDiffScope(
    target,
    baseRef as string,
    headRef as string,
    (absolutePath) => Boolean(registry.findAdapterForPath(absolutePath)),
  );

  if (!diffScope.success) {
    return diffScope;
  }

  return diffScope;
}

/**
 * Lists changed files for a git diff without filtering to source-adapter extensions.
 * Used by the secrets scanner so `.env`, keys, and config files are not skipped.
 */
export function resolveSecretsScanScope(
  target: CheckResolvedTarget,
  baseRef: string | undefined,
  headRef: string | undefined,
):
  | { success: true; data: CheckResolvedScope }
  | { success: false; diagnostics: Diagnostic[] } {
  if ((baseRef && !headRef) || (!baseRef && headRef)) {
    return {
      success: false,
      diagnostics: [
        createCheckRuntimeDiagnostic(
          'cli.argument.invalid',
          'Expected `--base` and `--head` to be provided together.',
        ),
      ],
    };
  }

  if (!baseRef && !headRef) {
    const files = target.isDirectory
      ? walkFiles(target.absolutePath)
      : [target.absolutePath];

    return {
      success: true,
      data: {
        scope: {
          mode: 'repo',
        },
        files,
        changedRangesByAbsolutePath: new Map<string, DiffRange[]>(),
      },
    };
  }

  return resolveRepositoryDiffScope(
    target,
    baseRef as string,
    headRef as string,
    () => true,
  );
}

function resolveRepositoryDiffScope(
  target: CheckResolvedTarget,
  baseRef: string,
  headRef: string,
  includeAbsolutePath: (absolutePath: string) => boolean,
):
  | { success: true; data: CheckResolvedScope }
  | { success: false; diagnostics: Diagnostic[] } {
  if (!target.repoRoot) {
    return {
      success: false,
      diagnostics: [
        createCheckRuntimeDiagnostic(
          'cli.git.not-repository',
          'Diff mode requires the target path to be inside a git repository.',
          {
            target: target.absolutePath,
          },
        ),
      ],
    };
  }

  const changedFilesResult = runGitCommand(target.repoRoot, [
    'diff',
    '--name-only',
    baseRef,
    headRef,
    '--',
  ]);

  if (!changedFilesResult.success) {
    const { diagnostics } = changedFilesResult as Extract<
      typeof changedFilesResult,
      { success: false }
    >;
    return {
      success: false,
      diagnostics,
    };
  }

  const diffResult = runGitCommand(target.repoRoot, [
    'diff',
    '--no-color',
    '--no-ext-diff',
    '--unified=0',
    baseRef,
    headRef,
    '--',
  ]);

  if (!diffResult.success) {
    const { diagnostics } = diffResult as Extract<
      typeof diffResult,
      { success: false }
    >;
    return {
      success: false,
      diagnostics,
    };
  }

  const changedRangesByRelativePath = parseGitDiffChangedRanges(diffResult.stdout);
  const files = changedFilesResult.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => resolve(target.repoRoot as string, line))
    .filter(
      (absolutePath) =>
        includeAbsolutePath(absolutePath) &&
        (target.isDirectory
          ? isPathWithinDirectory(target.absolutePath, absolutePath)
          : resolve(absolutePath) === target.absolutePath),
    )
    .filter((absolutePath) => {
      try {
        return statSync(absolutePath).isFile();
      } catch {
        return false;
      }
    })
    .sort((left, right) => left.localeCompare(right));
  const changedRangesByAbsolutePath = new Map<string, DiffRange[]>();

  for (const absolutePath of files) {
    const relativePath = toPosixPath(relative(target.repoRoot, absolutePath));
    changedRangesByAbsolutePath.set(
      absolutePath,
      changedRangesByRelativePath.get(relativePath) ?? [],
    );
  }

  return {
    success: true,
    data: {
      scope: {
        mode: 'diff',
        base: baseRef,
        head: headRef,
        changedFileCount: files.length,
      },
      files,
      changedRangesByAbsolutePath,
    },
  };
}

export function filterIgnoredPaths(
  files: readonly string[],
  changedRangesByAbsolutePath: ReadonlyMap<string, DiffRange[]>,
  displayRoot: string,
  includeTests: boolean,
  ignorePaths: readonly string[],
): { files: string[]; changedRangesByAbsolutePath: Map<string, DiffRange[]> } {
  const nextFiles = files.filter((absolutePath) => {
    const displayPath = toDisplayPath(displayRoot, absolutePath);

    if (
      !includeTests &&
      defaultIgnoredTestPatterns.some((pattern) =>
        minimatch(displayPath, pattern, { dot: true }),
      )
    ) {
      return false;
    }

    if (
      defaultIgnoredPathPatterns.some((pattern) =>
        minimatch(displayPath, pattern, { dot: true }),
      )
    ) {
      return false;
    }

    return !ignorePaths.some((pattern) =>
      minimatch(displayPath, pattern, { dot: true }),
    );
  });

  return {
    files: nextFiles,
    changedRangesByAbsolutePath: new Map(
      nextFiles.map((absolutePath) => [
        absolutePath,
        changedRangesByAbsolutePath.get(absolutePath) ?? [],
      ]),
    ),
  };
}
