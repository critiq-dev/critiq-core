import {
  loadCritiqConfigForDirectory,
  normalizeSecretsScanConfig,
  type NormalizedCritiqConfig,
} from '@critiq/core-config';
import type { Diagnostic } from '@critiq/core-diagnostics';
import type { DiffRange } from '@critiq/core-rules-engine';
import { readFile } from 'node:fs/promises';

import { createPathIgnoreFilter } from './path-filter';
import {
  resolveCheckTarget,
  resolveSecretsScanScope,
} from './scope';
import {
  createCheckRuntimeDiagnostic,
  readTextFileSafe,
  toDisplayPath,
  type CheckResolvedScope,
  type CheckResolvedTarget,
} from './shared';

export interface ScanFileTextCacheEntry {
  success: true;
  text: string;
}

export interface ScanFileTextCacheFailure {
  success: false;
  diagnostics: Diagnostic[];
}

export type ScanFileTextCacheResult =
  | ScanFileTextCacheEntry
  | ScanFileTextCacheFailure;

export interface ScanContext {
  cwd: string;
  target: string;
  displayRoot: string;
  resolvedTarget: CheckResolvedTarget;
  effectiveConfig: NormalizedCritiqConfig;
  repoScope: CheckResolvedScope;
  catalogFilteredScope: {
    files: string[];
    changedRangesByAbsolutePath: Map<string, DiffRange[]>;
  };
  analysisFilteredScope: {
    files: string[];
    changedRangesByAbsolutePath: Map<string, DiffRange[]>;
  };
  secretsFilteredScope: {
    files: string[];
    changedRangesByAbsolutePath: Map<string, DiffRange[]>;
  };
  fileTextCache: Map<string, ScanFileTextCacheResult>;
  readCachedText(absolutePath: string): ScanFileTextCacheResult;
  preloadFiles(absolutePaths: readonly string[]): Promise<void>;
}

export interface BuildScanContextOptions {
  cwd: string;
  target?: string;
  baseRef?: string;
  headRef?: string;
  staged?: boolean;
  secretsIncludeTests?: boolean;
  secretsIgnorePaths?: readonly string[];
}

export interface BuildScanContextSuccess {
  success: true;
  context: ScanContext;
}

export interface BuildScanContextFailure {
  success: false;
  diagnostics: Diagnostic[];
}

export type BuildScanContextResult =
  | BuildScanContextSuccess
  | BuildScanContextFailure;

const defaultConfig = (): NormalizedCritiqConfig => ({
  apiVersion: 'critiq.dev/v1alpha1' as const,
  kind: 'CritiqConfig' as const,
  catalogPackage: undefined,
  preset: 'recommended' as const,
  disableRules: [],
  disableCategories: [],
  disableLanguages: [],
  includeTests: false,
  ignorePaths: [],
  severityOverrides: {},
  secretsScan: normalizeSecretsScanConfig(undefined),
});

function filterScopeFiles(
  files: readonly string[],
  changedRangesByAbsolutePath: ReadonlyMap<string, DiffRange[]>,
  displayRoot: string,
  includeTests: boolean,
  ignorePaths: readonly string[],
): { files: string[]; changedRangesByAbsolutePath: Map<string, DiffRange[]> } {
  const filter = createPathIgnoreFilter(includeTests, ignorePaths);
  const nextFiles = files.filter((absolutePath) => {
    const displayPath = toDisplayPath(displayRoot, absolutePath);

    return !filter.shouldIgnore(displayPath);
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

function mergeSecretsIgnorePaths(
  config: NormalizedCritiqConfig,
  optionPaths: readonly string[] | undefined,
): string[] {
  return Array.from(
    new Set([
      ...config.ignorePaths,
      ...config.secretsScan.ignorePaths,
      ...(optionPaths ?? []),
    ]),
  ).sort((left, right) => left.localeCompare(right));
}

export function buildScanContext(
  options: BuildScanContextOptions,
): BuildScanContextResult {
  const cwd = options.cwd;
  const target = options.target ?? '.';
  const resolvedTarget = resolveCheckTarget(cwd, target);

  if (!resolvedTarget.success) {
    const { diagnostics } = resolvedTarget as Extract<
      typeof resolvedTarget,
      { success: false }
    >;

    return { success: false, diagnostics };
  }

  const loadedConfig = loadCritiqConfigForDirectory(
    resolvedTarget.data.displayRoot,
  );
  let effectiveConfig = defaultConfig();

  if (loadedConfig.success) {
    effectiveConfig = loadedConfig.data;
  } else {
    const diagnostics = (
      loadedConfig as Extract<typeof loadedConfig, { success: false }>
    ).diagnostics;

    if (
      diagnostics.length !== 1 ||
      diagnostics[0]?.code !== 'config.file.not-found'
    ) {
      return { success: false, diagnostics };
    }
  }

  const resolvedScope = resolveSecretsScanScope(
    resolvedTarget.data,
    options.baseRef,
    options.headRef,
    options.staged ?? false,
  );

  if (!resolvedScope.success) {
    const { diagnostics } = resolvedScope as Extract<
      typeof resolvedScope,
      { success: false }
    >;

    return { success: false, diagnostics };
  }

  const displayRoot = resolvedTarget.data.displayRoot;
  const secretsIncludeTests =
    options.secretsIncludeTests ?? effectiveConfig.includeTests;
  const secretsIgnorePaths = mergeSecretsIgnorePaths(
    effectiveConfig,
    options.secretsIgnorePaths,
  );

  const catalogFilteredScope = filterScopeFiles(
    resolvedScope.data.files,
    resolvedScope.data.changedRangesByAbsolutePath,
    displayRoot,
    effectiveConfig.includeTests,
    effectiveConfig.ignorePaths,
  );
  const analysisFilteredScope = filterScopeFiles(
    resolvedScope.data.files,
    resolvedScope.data.changedRangesByAbsolutePath,
    displayRoot,
    true,
    effectiveConfig.ignorePaths,
  );
  const secretsFilteredScope = filterScopeFiles(
    resolvedScope.data.files,
    resolvedScope.data.changedRangesByAbsolutePath,
    displayRoot,
    secretsIncludeTests,
    secretsIgnorePaths,
  );

  const fileTextCache = new Map<string, ScanFileTextCacheResult>();

  const context: ScanContext = {
    cwd,
    target,
    displayRoot,
    resolvedTarget: resolvedTarget.data,
    effectiveConfig,
    repoScope: resolvedScope.data,
    catalogFilteredScope,
    analysisFilteredScope,
    secretsFilteredScope,
    fileTextCache,
    readCachedText(absolutePath: string): ScanFileTextCacheResult {
      const cached = fileTextCache.get(absolutePath);

      if (cached) {
        return cached;
      }

      const readResult = readTextFileSafe(absolutePath);
      const stored: ScanFileTextCacheResult = readResult.success
        ? { success: true, text: readResult.text }
        : {
            success: false,
            diagnostics: (
              readResult as Extract<typeof readResult, { success: false }>
            ).diagnostics,
          };
      fileTextCache.set(absolutePath, stored);

      return stored;
    },
    async preloadFiles(absolutePaths: readonly string[]): Promise<void> {
      const concurrency = DEFAULT_PRELOAD_CONCURRENCY;

      for (let index = 0; index < absolutePaths.length; index += concurrency) {
        await preloadFileBatch(
          absolutePaths.slice(index, index + concurrency),
          fileTextCache,
        );
      }
    },
  };

  return {
    success: true,
    context,
  };
}

export function collectPreloadPaths(context: ScanContext): string[] {
  const paths = new Set<string>([
    ...context.catalogFilteredScope.files,
    ...context.analysisFilteredScope.files,
    ...context.secretsFilteredScope.files,
  ]);

  return [...paths].sort((left, right) => left.localeCompare(right));
}

const DEFAULT_PRELOAD_CONCURRENCY = 64;

async function preloadFileBatch(
  absolutePaths: readonly string[],
  fileTextCache: Map<string, ScanFileTextCacheResult>,
): Promise<void> {
  await Promise.all(
    absolutePaths.map(async (absolutePath) => {
      if (fileTextCache.has(absolutePath)) {
        return;
      }

      try {
        const text = await readFile(absolutePath, 'utf8');
        fileTextCache.set(absolutePath, { success: true, text });
      } catch (error) {
        fileTextCache.set(absolutePath, {
          success: false,
          diagnostics: [
            createCheckRuntimeDiagnostic(
              'runtime.internal.error',
              error instanceof Error
                ? error.message
                : 'Unexpected source file read failure.',
              {
                path: absolutePath,
              },
            ),
          ],
        });
      }
    }),
  );
}

export async function preloadScanContextFiles(
  context: ScanContext,
  options?: { concurrency?: number },
): Promise<void> {
  const concurrency = options?.concurrency ?? DEFAULT_PRELOAD_CONCURRENCY;
  const paths = collectPreloadPaths(context);

  for (let index = 0; index < paths.length; index += concurrency) {
    await preloadFileBatch(
      paths.slice(index, index + concurrency),
      context.fileTextCache,
    );
  }
}
