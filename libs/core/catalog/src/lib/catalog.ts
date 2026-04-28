import {
  createDiagnostic,
  DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
  DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
  DIAGNOSTIC_CODE_YAML_MAPPING_DUPLICATE_KEY,
  DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
  type Diagnostic,
} from '@critiq/core-diagnostics';
import type { NormalizedCritiqConfig } from '@critiq/core-config';
import type { NormalizedRule } from '@critiq/core-ir';
import {
  loadYamlText,
  type YamlLoadFailure,
  type YamlLoadIssue,
} from '@critiq/util-yaml-loader';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, extname, parse, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { z } from 'zod';

const catalogApiVersion = 'critiq.dev/v1alpha1' as const;
const catalogKind = 'RuleCatalog' as const;
const defaultCatalogFilename = 'catalog.yaml' as const;
const supportedPresetSchema = z.enum([
  'recommended',
  'strict',
  'security',
  'experimental',
]);

export const RULE_CATALOG_API_VERSION = catalogApiVersion;
export const RULE_CATALOG_KIND = catalogKind;
export const DEFAULT_RULE_CATALOG_FILENAME = defaultCatalogFilename;

export const ruleCatalogSchema = z
  .object({
    apiVersion: z.literal(catalogApiVersion),
    kind: z.literal(catalogKind),
    rules: z
      .array(
        z
          .object({
            id: z.string().min(1),
            rulePath: z.string().min(1),
            presets: z.array(supportedPresetSchema).min(1),
          })
          .strict(),
      )
      .min(1),
  })
  .strict();

export type RuleCatalog = z.infer<typeof ruleCatalogSchema>;
export type CatalogPreset = z.infer<typeof supportedPresetSchema>;
export type RepositoryLanguage =
  | 'typescript'
  | 'javascript'
  | 'python'
  | 'go'
  | 'java'
  | 'php'
  | 'ruby'
  | 'rust';

export interface ResolvedCatalogPackage {
  packageName: string;
  packageRoot: string;
  entryPath: string;
  catalogPath: string;
}

export function validateRuleCatalog(
  input: unknown,
): { success: true; data: RuleCatalog } | { success: false; diagnostics: Diagnostic[] } {
  const result = ruleCatalogSchema.safeParse(input);

  if (result.success) {
    return {
      success: true,
      data: result.data,
    };
  }

  return {
    success: false,
    diagnostics: result.error.issues.map((issue) =>
      createDiagnostic({
        code: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
        message: issue.message,
        jsonPointer:
          issue.path.length === 0 ? '/' : `/${issue.path.map(String).join('/')}`,
      }),
    ),
  };
}

function issueToDiagnostic(issue: YamlLoadIssue): Diagnostic {
  switch (issue.kind) {
    case 'duplicate-key':
      return createDiagnostic({
        code: DIAGNOSTIC_CODE_YAML_MAPPING_DUPLICATE_KEY,
        message: issue.message,
        sourceSpan: issue.sourceSpan,
        details: issue.details,
      });
    case 'syntax':
    case 'multi-document':
      return createDiagnostic({
        code: DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
        message: issue.message,
        sourceSpan: issue.sourceSpan,
        details: issue.details,
      });
    default:
      return createDiagnostic({
        code: DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
        message: issue.message,
        sourceSpan: issue.sourceSpan,
        details: issue.details,
      });
  }
}

export function loadRuleCatalogText(
  text: string,
  path: string,
): { success: true; data: RuleCatalog; path: string; uri: string } | { success: false; diagnostics: Diagnostic[]; path: string; uri: string } {
  const uri = pathToFileURL(path).href;
  const loaded = loadYamlText(text, uri);

  if (!loaded.success) {
    const failure = loaded as YamlLoadFailure;
    return {
      success: false,
      diagnostics: failure.issues.map(issueToDiagnostic),
      path,
      uri,
    };
  }

  const validated = validateRuleCatalog(loaded.data);

  if (!validated.success) {
    const failure = validated as Extract<typeof validated, { success: false }>;

    return {
      success: false,
      diagnostics: failure.diagnostics,
      path,
      uri,
    };
  }

  return {
    success: true,
    data: validated.data,
    path,
    uri,
  };
}

export function loadRuleCatalogFile(
  path: string,
): { success: true; data: RuleCatalog; path: string; uri: string } | { success: false; diagnostics: Diagnostic[]; path: string; uri: string } {
  try {
    return loadRuleCatalogText(readFileSync(path, 'utf8'), path);
  } catch (error) {
    const uri = pathToFileURL(path).href;
    const filesystemErrorCode =
      typeof error === 'object' &&
      error !== null &&
      'code' in error &&
      typeof error.code === 'string'
        ? error.code
        : undefined;
    const code =
      filesystemErrorCode === 'ENOENT'
        ? 'catalog.file.not-found'
        : DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR;
    const message =
      code === 'catalog.file.not-found'
        ? `No rule catalog file was found at \`${path}\`.`
        : error instanceof Error
          ? error.message
          : 'Unexpected rule catalog load failure.';

    return {
      success: false,
      diagnostics: [
        createDiagnostic({
          code,
          message,
          details: {
            path,
          },
        }),
      ],
      path,
      uri,
    };
  }
}

function tryResolvePackageEntry(packageName: string, fromPath: string): string | null {
  try {
    return createRequire(fromPath).resolve(packageName);
  } catch {
    return null;
  }
}

function findPackageRootFromEntryPath(
  packageName: string,
  entryPath: string,
): string {
  let currentDirectory = dirname(entryPath);
  const filesystemRoot = parse(currentDirectory).root;

  while (currentDirectory !== filesystemRoot) {
    const packageJsonPath = resolve(currentDirectory, 'package.json');

    if (existsSync(packageJsonPath)) {
      try {
        const packageJson = JSON.parse(
          readFileSync(packageJsonPath, 'utf8'),
        ) as { name?: string };

        if (packageJson.name === packageName) {
          return currentDirectory;
        }
      } catch {
        // Ignore malformed package.json files and continue walking upward.
      }
    }

    currentDirectory = dirname(currentDirectory);
  }

  return dirname(entryPath);
}

export function resolveCatalogPackage(
  cwd: string,
  packageName: string,
  additionalResolverBasePaths: readonly string[] = [],
): { success: true; data: ResolvedCatalogPackage } | { success: false; diagnostics: Diagnostic[] } {
  const resolverBases = [
    resolve(cwd, '__critiq_catalog_resolver__.js'),
    ...additionalResolverBasePaths.map((basePath) =>
      resolve(basePath, '__critiq_catalog_resolver__.js'),
    ),
    __filename,
  ];
  const localEntryPath = resolverBases
    .map((basePath) => tryResolvePackageEntry(packageName, basePath))
    .find((entryPath) => entryPath !== null);

  if (!localEntryPath) {
    return {
      success: false,
      diagnostics: [
        createDiagnostic({
          code: 'catalog.package.not-found',
          message: `Unable to resolve catalog package \`${packageName}\`.`,
          details: {
            packageName,
          },
        }),
      ],
    };
  }

  const packageRoot = findPackageRootFromEntryPath(packageName, localEntryPath);

  return {
    success: true,
    data: {
      packageName,
      packageRoot,
      entryPath: localEntryPath,
      catalogPath: resolve(packageRoot, defaultCatalogFilename),
    },
  };
}

export function resolveCatalogRulePaths(
  catalog: RuleCatalog,
  packageRoot: string,
  preset: CatalogPreset,
): Array<{ id: string; rulePath: string }> {
  return catalog.rules
    .filter((entry) => entry.presets.includes(preset))
    .map((entry) => ({
      id: entry.id,
      rulePath: resolve(packageRoot, entry.rulePath),
    }));
}

export function detectRepositoryLanguages(
  filePaths: readonly string[],
): RepositoryLanguage[] {
  const detected = new Set<RepositoryLanguage>();

  for (const filePath of filePaths) {
    const extension = extname(filePath).toLowerCase();

    if (extension === '.ts' || extension === '.tsx') {
      detected.add('typescript');
    }

    if (extension === '.js' || extension === '.jsx') {
      detected.add('javascript');
    }

    if (extension === '.py') {
      detected.add('python');
    }

    if (extension === '.go') {
      detected.add('go');
    }

    if (extension === '.java') {
      detected.add('java');
    }

    if (extension === '.php') {
      detected.add('php');
    }

    if (extension === '.rb') {
      detected.add('ruby');
    }

    if (extension === '.rs') {
      detected.add('rust');
    }
  }

  return [...detected].sort();
}

export function filterNormalizedRulesForCatalog(
  rules: readonly NormalizedRule[],
  config: NormalizedCritiqConfig,
  detectedLanguages: readonly RepositoryLanguage[],
): NormalizedRule[] {
  const effectiveLanguages = detectedLanguages.filter(
    (language) => !config.disableLanguages.includes(language),
  );

  return rules.filter((rule) => {
    if (config.disableRules.includes(rule.ruleId)) {
      return false;
    }

    if (
      config.disableCategories.some(
        (disabledCategory) =>
          rule.emit.finding.category === disabledCategory ||
          rule.emit.finding.category.startsWith(`${disabledCategory}.`),
      )
    ) {
      return false;
    }

    return (
      rule.scope.languages.includes('all') ||
      rule.scope.languages.some((language) =>
        effectiveLanguages.includes(language as RepositoryLanguage),
      )
    );
  });
}
