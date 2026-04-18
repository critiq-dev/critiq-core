import {
  createDiagnostic,
  type Diagnostic,
  DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
  DIAGNOSTIC_CODE_YAML_MAPPING_DUPLICATE_KEY,
  DIAGNOSTIC_CODE_YAML_SYNTAX_INVALID,
  type JsonPointer,
  type SourceSpan,
} from '@critiq/core-diagnostics';
import {
  loadYamlText,
  type YamlLoadFailure,
  type YamlLoadIssue,
  type YamlSourceMap,
} from '@critiq/util-yaml-loader';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

/**
 * Represents the source mapping stored for a single JSON Pointer.
 */
export interface RuleSourceMapEntry {
  keySpan?: SourceSpan;
  valueSpan: SourceSpan;
}

/**
 * Represents the pointer-indexed source map attached to a loaded rule document.
 */
export type RuleSourceMap = Record<JsonPointer, RuleSourceMapEntry>;

/**
 * Represents a source-aware loaded rule document.
 */
export interface LoadedRuleDocument {
  uri: string;
  document: unknown;
  sourceMap: RuleSourceMap;
}

/**
 * Represents a successful rule load result.
 */
export interface LoadRuleSuccess {
  success: true;
  data: LoadedRuleDocument;
}

/**
 * Represents a failed rule load result.
 */
export interface LoadRuleFailure {
  success: false;
  diagnostics: Diagnostic[];
}

/**
 * Represents the result returned by loadRuleText() and loadRuleFile().
 */
export type LoadRuleResult = LoadRuleSuccess | LoadRuleFailure;

function toSourceMap(sourceMap: YamlSourceMap): RuleSourceMap {
  return Object.fromEntries(
    Object.entries(sourceMap).map(([pointer, entry]) => [
      pointer,
      {
        keySpan: entry.keySpan,
        valueSpan: entry.valueSpan,
      },
    ]),
  );
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
    case 'internal':
    default:
      return createDiagnostic({
        code: DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
        message: issue.message,
        sourceSpan: issue.sourceSpan,
        details: issue.details,
      });
  }
}

function failureResult(result: YamlLoadFailure): LoadRuleFailure {
  return {
    success: false,
    diagnostics: result.issues.map(issueToDiagnostic),
  };
}

/**
 * Loads rule YAML text into a source-aware wrapper without performing contract
 * or semantic validation.
 */
export function loadRuleText(text: string, uri: string): LoadRuleResult {
  const result = loadYamlText(text, uri);

  if (!result.success) {
    return failureResult(result as YamlLoadFailure);
  }

  return {
    success: true,
    data: {
      uri: result.uri,
      document: result.data,
      sourceMap: toSourceMap(result.sourceMap),
    },
  };
}

/**
 * Reads a YAML rule file from disk and delegates parsing to loadRuleText().
 */
export function loadRuleFile(path: string): LoadRuleResult {
  try {
    const text = readFileSync(path, 'utf8');
    const uri = pathToFileURL(path).href;

    return loadRuleText(text, uri);
  } catch (error) {
    return {
      success: false,
      diagnostics: [
        createDiagnostic({
          code: DIAGNOSTIC_CODE_RUNTIME_INTERNAL_ERROR,
          message:
            error instanceof Error
              ? error.message
              : 'Unexpected rule file loading failure.',
          details: {
            path,
          },
        }),
      ],
    };
  }
}
