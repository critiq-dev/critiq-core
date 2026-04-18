import {
  createDiagnostic,
  createJsonPointer,
  type Diagnostic,
  DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
  type JsonPointer,
  type SourceSpan,
} from '@critiq/core-diagnostics';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { ZodIssue, ZodIssueCode } from 'zod';

import {
  loadRuleText,
  type LoadedRuleDocument,
  type LoadRuleFailure,
  type RuleSourceMap,
} from './rules-dsl-loader';
import {
  ruleDocumentV0Alpha1Schema,
  type RuleConditionNode,
  type RuleDocumentV0Alpha1,
} from './rules-dsl-schema';
import { scanRuleTemplateField } from './rules-dsl-template-variables';

const dottedSlugRuleIdPattern = /^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$/;
const ossCatalogRuleIdPattern = /^CRQ-[A-Z]{3}-\d{3}$/;
const semanticDiagnosticSeverity = 'error' as const;

/**
 * Stable semantic diagnostic code for invalid rule identifiers.
 */
export const DIAGNOSTIC_CODE_RULE_SEMANTIC_RULE_ID_INVALID =
  'semantic.rule-id.invalid' as const;

/**
 * Stable semantic diagnostic code for empty `all` groups.
 */
export const DIAGNOSTIC_CODE_RULE_SEMANTIC_LOGICAL_EMPTY_ALL =
  'semantic.logical.empty-all' as const;

/**
 * Stable semantic diagnostic code for empty `any` groups.
 */
export const DIAGNOSTIC_CODE_RULE_SEMANTIC_LOGICAL_EMPTY_ANY =
  'semantic.logical.empty-any' as const;

/**
 * Stable semantic diagnostic code for mixed syntax and fact predicates.
 */
export const DIAGNOSTIC_CODE_RULE_SEMANTIC_MATCH_MIXED_DOMAINS =
  'semantic.match.mixed-domains' as const;

/**
 * Stable semantic diagnostic code for duplicate bind names.
 */
export const DIAGNOSTIC_CODE_RULE_SEMANTIC_CAPTURE_DUPLICATE_BIND =
  'semantic.capture.duplicate-bind' as const;

/**
 * Stable semantic diagnostic code for unreachable capture references.
 */
export const DIAGNOSTIC_CODE_RULE_SEMANTIC_CAPTURE_UNREACHABLE_REFERENCE =
  'semantic.capture.unreachable-reference' as const;

/**
 * Stable semantic diagnostic code for invalid template variables.
 */
export const DIAGNOSTIC_CODE_RULE_SEMANTIC_TEMPLATE_INVALID_VARIABLE =
  'semantic.template.invalid-variable' as const;

/**
 * Stable semantic diagnostic code for empty language scope.
 */
export const DIAGNOSTIC_CODE_RULE_SEMANTIC_SCOPE_LANGUAGES_EMPTY =
  'semantic.scope.languages.empty' as const;

/**
 * Stable semantic diagnostic code for semantically empty emit content.
 */
export const DIAGNOSTIC_CODE_RULE_SEMANTIC_EMIT_EMPTY =
  'semantic.emit.empty' as const;

/**
 * Represents a source-aware rule document that has passed contract validation.
 */
export interface ContractValidatedRuleDocument {
  uri: string;
  document: RuleDocumentV0Alpha1;
  sourceMap: RuleSourceMap;
}

/**
 * Represents a successful contract validation result.
 */
export interface RuleContractValidationSuccess {
  success: true;
  data: ContractValidatedRuleDocument;
}

/**
 * Represents a failed contract validation result.
 */
export interface RuleContractValidationFailure {
  success: false;
  diagnostics: Diagnostic[];
}

/**
 * Represents the result returned by validateLoadedRuleDocumentContract().
 */
export type RuleContractValidationResult =
  | RuleContractValidationSuccess
  | RuleContractValidationFailure;

/**
 * Represents a successful semantic validation result.
 */
export interface RuleSemanticValidationSuccess {
  success: true;
  diagnostics: [];
}

/**
 * Represents a failed semantic validation result.
 */
export interface RuleSemanticValidationFailure {
  success: false;
  diagnostics: Diagnostic[];
}

/**
 * Represents the result returned by validateRuleDocumentSemantics().
 */
export type RuleSemanticValidationResult =
  | RuleSemanticValidationSuccess
  | RuleSemanticValidationFailure;

/**
 * Represents a successful composed validation result.
 */
export interface RuleValidationSuccess {
  success: true;
  data: ContractValidatedRuleDocument;
  diagnostics: [];
}

/**
 * Represents a failed composed validation result.
 */
export interface RuleValidationFailure {
  success: false;
  diagnostics: Diagnostic[];
}

/**
 * Represents the result returned by the composed rule validators.
 */
export type RuleValidationResult = RuleValidationSuccess | RuleValidationFailure;

interface ConditionAnalysisResult {
  diagnostics: Diagnostic[];
  reachableCaptures: Set<string>;
  domains: Set<'fact' | 'syntax'>;
}

function getSourceSpan(
  sourceMap: RuleSourceMap,
  pointer: JsonPointer,
): SourceSpan | undefined {
  let currentPointer = pointer;

  while (true) {
    const entry = sourceMap[currentPointer];

    if (entry) {
      return entry.valueSpan;
    }

    if (currentPointer === '/') {
      return undefined;
    }

    const lastSlashIndex = currentPointer.lastIndexOf('/');

    currentPointer =
      lastSlashIndex <= 0 ? '/' : currentPointer.slice(0, lastSlashIndex);
  }
}

function createSemanticDiagnostic(
  code: string,
  message: string,
  pointer: JsonPointer,
  sourceMap: RuleSourceMap,
  details?: Record<string, unknown>,
): Diagnostic {
  return createDiagnostic({
    code,
    severity: semanticDiagnosticSeverity,
    message,
    jsonPointer: pointer,
    sourceSpan: getSourceSpan(sourceMap, pointer),
    details,
  });
}

function toIssuePath(path: (string | number)[]): JsonPointer {
  return createJsonPointer(path);
}

function contractIssueToDiagnostic(
  issue: ZodIssue,
  sourceMap: RuleSourceMap,
): Diagnostic {
  const pointer = toIssuePath(issue.path);
  const details: Record<string, unknown> = {
    code: issue.code,
  };

  if (issue.code === ZodIssueCode.invalid_type) {
    details['expected'] = issue.expected;
    details['received'] = issue.received;
  }

  if (issue.code === ZodIssueCode.invalid_enum_value) {
    details['expected'] = issue.options.join('|');
    details['received'] = String(issue.received);
  }

  if (issue.code === ZodIssueCode.unrecognized_keys) {
    details['expected'] = 'No unknown keys';
    details['received'] = issue.keys.join('|');
  }

  if (
    issue.code === ZodIssueCode.invalid_string &&
    issue.validation !== 'regex' &&
    typeof issue.validation === 'string'
  ) {
    details['expected'] = issue.validation;
  }

  return createDiagnostic({
    code: DIAGNOSTIC_CODE_CONTRACT_VALIDATION_INVALID,
    message: issue.message,
    jsonPointer: pointer,
    sourceSpan: getSourceSpan(sourceMap, pointer),
    details,
  });
}

function trimSegments(
  pointer: JsonPointer,
  segment: string | number,
): JsonPointer {
  return pointer === '/' ? `/${segment}` : `${pointer}/${segment}`;
}

function intersectCaptureSets(sets: Set<string>[]): Set<string> {
  if (sets.length === 0) {
    return new Set();
  }

  const intersection = new Set(sets[0]);

  for (const capture of intersection) {
    if (!sets.every((set) => set.has(capture))) {
      intersection.delete(capture);
    }
  }

  return intersection;
}

function analyzeCondition(
  condition: RuleConditionNode,
  pointer: JsonPointer,
  inheritedCaptures: Set<string>,
  sourceMap: RuleSourceMap,
): ConditionAnalysisResult {
  if ('all' in condition) {
    const allPointer = trimSegments(pointer, 'all');
    const diagnostics: Diagnostic[] = [];

    if (condition.all.length === 0) {
      diagnostics.push(
        createSemanticDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_LOGICAL_EMPTY_ALL,
          'Logical `all` groups must contain at least one child condition.',
          allPointer,
          sourceMap,
        ),
      );
    }

    let captures = new Set(inheritedCaptures);
    const domains = new Set<'fact' | 'syntax'>();

    condition.all.forEach((child, index) => {
      const result = analyzeCondition(
        child,
        trimSegments(allPointer, index),
        captures,
        sourceMap,
      );

      diagnostics.push(...result.diagnostics);
      captures = result.reachableCaptures;
      result.domains.forEach((domain) => domains.add(domain));
    });

    return {
      diagnostics,
      reachableCaptures: captures,
      domains,
    };
  }

  if ('any' in condition) {
    const anyPointer = trimSegments(pointer, 'any');
    const diagnostics: Diagnostic[] = [];

    if (condition.any.length === 0) {
      diagnostics.push(
        createSemanticDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_LOGICAL_EMPTY_ANY,
          'Logical `any` groups must contain at least one child condition.',
          anyPointer,
          sourceMap,
        ),
      );
    }

    const branchResults = condition.any.map((child, index) =>
      analyzeCondition(
        child,
        trimSegments(anyPointer, index),
        new Set(inheritedCaptures),
        sourceMap,
      ),
    );

    for (const result of branchResults) {
      diagnostics.push(...result.diagnostics);
    }

    const reachableCaptures =
      branchResults.length === 0
        ? new Set(inheritedCaptures)
        : intersectCaptureSets(
            branchResults.map((result) => result.reachableCaptures),
          );

    return {
      diagnostics,
      reachableCaptures,
      domains: branchResults.reduce(
        (result, branch) => {
          branch.domains.forEach((domain) => result.add(domain));
          return result;
        },
        new Set<'fact' | 'syntax'>(),
      ),
    };
  }

  if ('not' in condition) {
    const notPointer = trimSegments(pointer, 'not');
    const result = analyzeCondition(
      condition.not,
      notPointer,
      new Set(inheritedCaptures),
      sourceMap,
    );

    return {
      diagnostics: result.diagnostics,
      reachableCaptures: new Set(inheritedCaptures),
      domains: new Set(result.domains),
    };
  }

  let predicateKind: 'ancestor' | 'fact' | 'node';
  let predicate: {
    bind?: string;
  };

  if ('node' in condition) {
    predicateKind = 'node';
    predicate = condition.node;
  } else if ('ancestor' in condition) {
    predicateKind = 'ancestor';
    predicate = condition.ancestor;
  } else {
    predicateKind = 'fact';
    predicate = condition.fact;
  }

  const predicatePointer = trimSegments(pointer, predicateKind);
  const diagnostics: Diagnostic[] = [];
  const reachableCaptures = new Set(inheritedCaptures);

  if (predicate.bind) {
    const bindPointer = trimSegments(predicatePointer, 'bind');

    if (reachableCaptures.has(predicate.bind)) {
      diagnostics.push(
        createSemanticDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_CAPTURE_DUPLICATE_BIND,
          `Capture \`${predicate.bind}\` is already bound in this logical branch.`,
          bindPointer,
          sourceMap,
          {
            bind: predicate.bind,
          },
        ),
      );
    } else {
      reachableCaptures.add(predicate.bind);
    }
  }

  return {
    diagnostics,
    reachableCaptures,
    domains: new Set([predicateKind === 'fact' ? 'fact' : 'syntax']),
  };
}

function validatePlaceholderExpression(
  reference: ReturnType<typeof scanRuleTemplateField>['references'][number],
  pointer: JsonPointer,
  sourceMap: RuleSourceMap,
  reachableCaptures: Set<string>,
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const segments = reference.expression.split('.');
  const root = segments[0];

  if (root === 'captures') {
    const captureName = segments[1];
    const field = segments[2];

    if (segments.length !== 3 || !captureName || !field) {
      diagnostics.push(
        createSemanticDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_TEMPLATE_INVALID_VARIABLE,
          `Template variable \`${reference.raw}\` is not a supported capture reference.`,
          pointer,
          sourceMap,
          {
            expression: reference.expression,
          },
        ),
      );

      return diagnostics;
    }

    if (!['text', 'kind', 'path'].includes(field)) {
      diagnostics.push(
        createSemanticDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_TEMPLATE_INVALID_VARIABLE,
          `Template variable \`${reference.raw}\` references an unsupported capture field.`,
          pointer,
          sourceMap,
          {
            expression: reference.expression,
          },
        ),
      );

      return diagnostics;
    }

    if (!reachableCaptures.has(captureName)) {
      diagnostics.push(
        createSemanticDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_CAPTURE_UNREACHABLE_REFERENCE,
          `Template variable \`${reference.raw}\` references capture \`${captureName}\`, which is not reachable from this rule condition.`,
          pointer,
          sourceMap,
          {
            expression: reference.expression,
            capture: captureName,
          },
        ),
      );
    }

    return diagnostics;
  }

  if (root === 'file') {
    if (segments.length !== 2 || !['path', 'language'].includes(segments[1])) {
      diagnostics.push(
        createSemanticDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_TEMPLATE_INVALID_VARIABLE,
          `Template variable \`${reference.raw}\` is not a supported file reference.`,
          pointer,
          sourceMap,
          {
            expression: reference.expression,
          },
        ),
      );
    }

    return diagnostics;
  }

  if (root === 'rule') {
    if (segments.length !== 2 || !['id', 'title'].includes(segments[1])) {
      diagnostics.push(
        createSemanticDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_TEMPLATE_INVALID_VARIABLE,
          `Template variable \`${reference.raw}\` is not a supported rule reference.`,
          pointer,
          sourceMap,
          {
            expression: reference.expression,
          },
        ),
      );
    }

    return diagnostics;
  }

  diagnostics.push(
    createSemanticDiagnostic(
      DIAGNOSTIC_CODE_RULE_SEMANTIC_TEMPLATE_INVALID_VARIABLE,
      `Template variable \`${reference.raw}\` uses an unsupported root.`,
      pointer,
      sourceMap,
      {
        expression: reference.expression,
      },
    ),
  );

  return diagnostics;
}

function validateTemplateField(
  value: string | undefined,
  pointer: JsonPointer,
  sourceMap: RuleSourceMap,
  reachableCaptures: Set<string>,
): Diagnostic[] {
  if (value === undefined) {
    return [];
  }

  const scan = scanRuleTemplateField(value);
  const diagnostics: Diagnostic[] = [];

  if (scan.malformed) {
    diagnostics.push(
      createSemanticDiagnostic(
        DIAGNOSTIC_CODE_RULE_SEMANTIC_TEMPLATE_INVALID_VARIABLE,
        'Template placeholders must use the `${...}` form.',
        pointer,
        sourceMap,
        {
          value,
        },
      ),
    );
  }

  for (const reference of scan.references) {
    diagnostics.push(
      ...validatePlaceholderExpression(
        reference,
        pointer,
        sourceMap,
        reachableCaptures,
      ),
    );
  }

  return diagnostics;
}

/**
 * Validates a source-aware loaded rule document against the public contract and
 * maps contract failures back to source spans when possible.
 */
export function validateLoadedRuleDocumentContract(
  loadedRuleDocument: LoadedRuleDocument,
): RuleContractValidationResult {
  const result = ruleDocumentV0Alpha1Schema.safeParse(loadedRuleDocument.document);

  if (!result.success) {
    return {
      success: false,
      diagnostics: result.error.issues.map((issue) =>
        contractIssueToDiagnostic(issue, loadedRuleDocument.sourceMap),
      ),
    };
  }

  return {
    success: true,
    data: {
      uri: loadedRuleDocument.uri,
      document: result.data,
      sourceMap: loadedRuleDocument.sourceMap,
    },
  };
}

/**
 * Runs v0 semantic validation on a contract-valid source-aware rule document.
 */
export function validateRuleDocumentSemantics(
  validatedRuleDocument: ContractValidatedRuleDocument,
): RuleSemanticValidationResult {
  const { document, sourceMap } = validatedRuleDocument;
  const diagnostics: Diagnostic[] = [];

  if (
    !dottedSlugRuleIdPattern.test(document.metadata.id) &&
    !ossCatalogRuleIdPattern.test(document.metadata.id)
  ) {
    diagnostics.push(
      createSemanticDiagnostic(
        DIAGNOSTIC_CODE_RULE_SEMANTIC_RULE_ID_INVALID,
        'Rule metadata.id must use either a dotted slug such as `ts.logging.no-console-log` or an OSS catalog code such as `CRQ-SEC-016`.',
        '/metadata/id',
        sourceMap,
        {
          received: document.metadata.id,
        },
      ),
    );
  }

  if (document.scope.languages.length === 0) {
    diagnostics.push(
      createSemanticDiagnostic(
        DIAGNOSTIC_CODE_RULE_SEMANTIC_SCOPE_LANGUAGES_EMPTY,
        'Rule scope.languages must contain at least one language.',
        '/scope/languages',
        sourceMap,
      ),
    );
  }

  const matchAnalysis = analyzeCondition(
    document.match,
    '/match',
    new Set<string>(),
    sourceMap,
  );

  diagnostics.push(...matchAnalysis.diagnostics);

  if (matchAnalysis.domains.size > 1) {
    diagnostics.push(
      createSemanticDiagnostic(
        DIAGNOSTIC_CODE_RULE_SEMANTIC_MATCH_MIXED_DOMAINS,
        'Rules cannot mix `fact` predicates with `node` or `ancestor` predicates in the same match tree.',
        '/match',
        sourceMap,
      ),
    );
  }

  const messageFields = [
    document.emit.message.title,
    document.emit.message.summary,
    document.emit.message.detail,
    document.emit.remediation?.summary,
  ];

  if (!messageFields.some((value) => typeof value === 'string' && value.trim().length > 0)) {
    diagnostics.push(
      createSemanticDiagnostic(
        DIAGNOSTIC_CODE_RULE_SEMANTIC_EMIT_EMPTY,
        'Rule emit content must contain at least one non-blank user-facing message field.',
        '/emit',
        sourceMap,
      ),
    );
  }

  diagnostics.push(
    ...validateTemplateField(
      document.emit.message.title,
      '/emit/message/title',
      sourceMap,
      matchAnalysis.reachableCaptures,
    ),
    ...validateTemplateField(
      document.emit.message.summary,
      '/emit/message/summary',
      sourceMap,
      matchAnalysis.reachableCaptures,
    ),
    ...validateTemplateField(
      document.emit.message.detail,
      '/emit/message/detail',
      sourceMap,
      matchAnalysis.reachableCaptures,
    ),
    ...validateTemplateField(
      document.emit.remediation?.summary,
      '/emit/remediation/summary',
      sourceMap,
      matchAnalysis.reachableCaptures,
    ),
  );

  if (diagnostics.length === 0) {
    return {
      success: true,
      diagnostics: [],
    };
  }

  return {
    success: false,
    diagnostics,
  };
}

/**
 * Validates an already-loaded source-aware rule document by running contract
 * validation first and semantic validation second.
 */
export function validateLoadedRuleDocument(
  loadedRuleDocument: LoadedRuleDocument,
): RuleValidationResult {
  const contractValidation = validateLoadedRuleDocumentContract(loadedRuleDocument);

  if (!contractValidation.success) {
    const failure = contractValidation as RuleContractValidationFailure;
    return {
      success: false,
      diagnostics: failure.diagnostics,
    };
  }

  const semanticValidation = validateRuleDocumentSemantics(contractValidation.data);

  if (!semanticValidation.success) {
    return {
      success: false,
      diagnostics: semanticValidation.diagnostics,
    };
  }

  return {
    success: true,
    data: contractValidation.data,
    diagnostics: [],
  };
}

/**
 * Loads rule YAML text and runs the full contract + semantic validation
 * pipeline.
 */
export function validateRuleTextDocument(
  text: string,
  uri: string,
): RuleValidationResult {
  const loadResult = loadRuleText(text, uri);

  if (!loadResult.success) {
    const failure = loadResult as LoadRuleFailure;

    return {
      success: false,
      diagnostics: failure.diagnostics,
    };
  }

  return validateLoadedRuleDocument(loadResult.data);
}

/**
 * Loads a rule file from disk and runs the full contract + semantic validation
 * pipeline.
 */
export function validateRuleFileDocument(path: string): RuleValidationResult {
  try {
    const text = readFileSync(path, 'utf8');
    const uri = pathToFileURL(path).href;

    return validateRuleTextDocument(text, uri);
  } catch (error) {
    const loadFailure: LoadRuleFailure = {
      success: false,
      diagnostics: [
        createDiagnostic({
          code: 'runtime.internal.error',
          message:
            error instanceof Error
              ? error.message
              : 'Unexpected rule file validation failure.',
          details: {
            path,
          },
        }),
      ],
    };

    return loadFailure;
  }
}
