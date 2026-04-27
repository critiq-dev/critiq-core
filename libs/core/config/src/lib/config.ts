import {
  createDiagnostic,
  DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
  DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
  DIAGNOSTIC_CODE_YAML_MAPPING_DUPLICATE_KEY,
  DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
  type Diagnostic,
} from '@critiq/core-diagnostics';
import {
  findingCategorySchema,
  findingSeveritySchema,
  type FindingCategory,
  type FindingSeverity,
} from '@critiq/core-finding-schema';
import {
  loadYamlText,
  type YamlLoadFailure,
  type YamlLoadIssue,
} from '@critiq/util-yaml-loader';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { z } from 'zod';

const configApiVersion = 'critiq.dev/v1alpha1' as const;
const configKind = 'CritiqConfig' as const;
const configLanguageSchema = z.enum([
  'typescript',
  'javascript',
  'ts',
  'js',
  'python',
  'go',
]);

export const CRITIQ_CONFIG_API_VERSION = configApiVersion;
export const CRITIQ_CONFIG_KIND = configKind;
export const CRITIQ_CONFIG_DEFAULT_PATH = '.critiq/config.yaml' as const;

export const critiqPresetSchema = z.enum([
  'recommended',
  'strict',
  'security',
  'experimental',
]);
export type CritiqPreset = z.infer<typeof critiqPresetSchema>;

export const critiqConfigSchema = z
  .object({
    apiVersion: z.literal(configApiVersion),
    kind: z.literal(configKind),
    catalog: z
      .object({
        package: z.string().min(1).optional(),
      })
      .strict()
      .optional(),
    preset: critiqPresetSchema.optional(),
    disableRules: z.array(z.string().min(1)).optional(),
    disableCategories: z.array(findingCategorySchema).optional(),
    disableLanguages: z.array(configLanguageSchema).optional(),
    includeTests: z.boolean().optional(),
    ignorePaths: z.array(z.string().min(1)).optional(),
    severityOverrides: z
      .record(z.string().min(1), findingSeveritySchema)
      .optional(),
  })
  .strict();

export type CritiqConfig = z.infer<typeof critiqConfigSchema>;
export type CritiqConfigLanguage = z.infer<typeof configLanguageSchema>;

export interface NormalizedCritiqConfig {
  apiVersion: typeof configApiVersion;
  kind: typeof configKind;
  catalogPackage?: string;
  preset: CritiqPreset;
  disableRules: string[];
  disableCategories: FindingCategory[];
  disableLanguages: Array<'typescript' | 'javascript' | 'python' | 'go'>;
  includeTests: boolean;
  ignorePaths: string[];
  severityOverrides: Record<string, FindingSeverity>;
}

export type CritiqConfigValidationResult =
  | { success: true; data: CritiqConfig }
  | {
      success: false;
      diagnostics: Diagnostic[];
    };

export type LoadCritiqConfigResult =
  | { success: true; data: NormalizedCritiqConfig; path: string; uri: string }
  | { success: false; diagnostics: Diagnostic[]; path: string; uri: string };

function normalizeStringArray(values: readonly string[] | undefined): string[] {
  if (!values) {
    return [];
  }

  return Array.from(
    new Set(
      values
        .map((value) => value.trim())
        .filter((value) => value.length > 0),
    ),
  ).sort();
}

function normalizeLanguage(
  language: CritiqConfigLanguage,
): 'typescript' | 'javascript' | 'python' | 'go' {
  if (language === 'ts' || language === 'typescript') {
    return 'typescript';
  }

  if (language === 'js' || language === 'javascript') {
    return 'javascript';
  }

  return language;
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

export function normalizeCritiqConfig(
  config: CritiqConfig,
): NormalizedCritiqConfig {
  return {
    apiVersion: configApiVersion,
    kind: configKind,
    catalogPackage:
      config.catalog?.package?.trim().length
        ? config.catalog.package.trim()
        : undefined,
    preset: config.preset ?? 'recommended',
    disableRules: normalizeStringArray(config.disableRules),
    disableCategories: Array.from(
      new Set(config.disableCategories ?? []),
    ).sort(),
    disableLanguages: Array.from(
      new Set((config.disableLanguages ?? []).map(normalizeLanguage)),
    ).sort(),
    includeTests: config.includeTests ?? false,
    ignorePaths: normalizeStringArray(config.ignorePaths),
    severityOverrides: Object.fromEntries(
      Object.entries(config.severityOverrides ?? {}).sort(([left], [right]) =>
        left.localeCompare(right),
      ),
    ),
  };
}

export function validateCritiqConfig(
  input: unknown,
): CritiqConfigValidationResult {
  const result = critiqConfigSchema.safeParse(input);

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

export function loadCritiqConfigText(
  text: string,
  path: string,
): LoadCritiqConfigResult {
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

  const validated = validateCritiqConfig(loaded.data);

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
    data: normalizeCritiqConfig(validated.data),
    path,
    uri,
  };
}

export function loadCritiqConfigFile(path: string): LoadCritiqConfigResult {
  try {
    return loadCritiqConfigText(readFileSync(path, 'utf8'), path);
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
        ? 'config.file.not-found'
        : DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR;
    const message =
      code === 'config.file.not-found'
        ? `No Critiq config file was found at \`${path}\`.`
        : error instanceof Error
          ? error.message
          : 'Unexpected Critiq config load failure.';

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

export function loadCritiqConfigForDirectory(
  directoryPath: string,
): LoadCritiqConfigResult {
  return loadCritiqConfigFile(resolve(directoryPath, CRITIQ_CONFIG_DEFAULT_PATH));
}
