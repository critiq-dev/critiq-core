import {
  aggregateDiagnostics,
  formatDiagnosticsForTerminal,
  type Diagnostic,
} from '@critiq/core-diagnostics';
import { normalizeRuleDocument } from '@critiq/core-ir';
import { formatRuleSpecRunAsJson, runRuleSpec } from '@critiq/testing-harness';
import {
  loadRuleFile,
  summarizeValidatedRuleDocument,
  validateLoadedRuleDocument,
  validateLoadedRuleDocumentContract,
  validateRuleDocumentSemantics,
  type LoadRuleResult,
  type RuleTemplateVariableMap,
} from '@critiq/core-rules-dsl';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  type CliRuntime,
  type ExplainCommandEnvelope,
  type ExplainParsedSummary,
  type NormalizeCommandEnvelope,
  type OutputFormat,
  type SingleFileCommandState,
  type TestCommandEnvelope,
  type TestSpecResult,
  type ValidateCommandEnvelope,
  type ValidateFileResult,
} from '../cli.types';
import {
  renderJson,
  renderSingleFilePretty,
  renderTestPretty,
  renderValidatePretty,
} from '../rendering/rules.rendering';
import { determineExitCode } from '../utils/determine-exit-code.util';
import { toDisplayPath } from '../utils/to-display-path.util';
import {
  resolveSingleFilePath,
  resolveTestTargets,
  resolveValidateTargets,
} from './rules-targets';

const DEFAULT_TEMPLATE_VARIABLES: RuleTemplateVariableMap = {
  'emit.message.title': [],
  'emit.message.summary': [],
  'emit.message.detail': [],
  'emit.remediation.summary': [],
};

function createParsedSummary(path: string, uri: string): ExplainParsedSummary {
  return {
    path,
    uri,
    ruleId: null,
    title: null,
    summary: null,
    phases: {
      load: 'skipped',
      contractValidation: 'skipped',
      semanticValidation: 'skipped',
      normalization: 'skipped',
    },
  };
}

function validateResultForFileSafe(
  absolutePath: string,
  cwd: string,
): ValidateFileResult {
  const displayPath = toDisplayPath(cwd, absolutePath);
  const uri = pathToFileURL(absolutePath).href;
  const loaded = loadRuleFile(absolutePath);

  if (!loaded.success) {
    const failure = loaded as Extract<LoadRuleResult, { success: false }>;

    return {
      path: displayPath,
      uri,
      success: false,
      diagnostics: failure.diagnostics,
    };
  }

  const validated = validateLoadedRuleDocument(loaded.data);

  if (!validated.success) {
    return {
      path: displayPath,
      uri,
      success: false,
      diagnostics: validated.diagnostics,
    };
  }

  return {
    path: displayPath,
    uri,
    success: true,
    diagnostics: [],
  };
}

function buildSingleFileState(
  absolutePath: string,
  cwd: string,
): SingleFileCommandState {
  const displayPath = toDisplayPath(cwd, absolutePath);
  const uri = pathToFileURL(absolutePath).href;
  const parsedSummary = createParsedSummary(displayPath, uri);
  const templateVariables = { ...DEFAULT_TEMPLATE_VARIABLES };

  const loadResult = loadRuleFile(absolutePath);

  parsedSummary.phases.load = loadResult.success ? 'success' : 'failure';

  if (!loadResult.success) {
    const failure = loadResult as Extract<LoadRuleResult, { success: false }>;

    return {
      displayPath,
      uri,
      parsedSummary,
      semanticStatus: {
        success: false,
        diagnostics: failure.diagnostics,
      },
      normalizedRule: null,
      ruleHash: null,
      templateVariables,
      diagnostics: failure.diagnostics,
    };
  }

  const contractValidation = validateLoadedRuleDocumentContract(
    loadResult.data,
  );

  parsedSummary.phases.contractValidation = contractValidation.success
    ? 'success'
    : 'failure';

  if (!contractValidation.success) {
    const failure = contractValidation as Extract<
      ReturnType<typeof validateLoadedRuleDocumentContract>,
      { success: false }
    >;

    return {
      displayPath,
      uri,
      parsedSummary,
      semanticStatus: {
        success: false,
        diagnostics: failure.diagnostics,
      },
      normalizedRule: null,
      ruleHash: null,
      templateVariables,
      diagnostics: failure.diagnostics,
    };
  }

  const explainSummary = summarizeValidatedRuleDocument(
    contractValidation.data,
  );

  parsedSummary.ruleId = explainSummary.ruleId;
  parsedSummary.title = explainSummary.title;
  parsedSummary.summary = explainSummary.summary;

  for (const [field, references] of Object.entries(
    explainSummary.templateVariables,
  )) {
    templateVariables[field as keyof RuleTemplateVariableMap] = references;
  }

  const semanticValidation = validateRuleDocumentSemantics(
    contractValidation.data,
  );

  parsedSummary.phases.semanticValidation = semanticValidation.success
    ? 'success'
    : 'failure';

  if (!semanticValidation.success) {
    return {
      displayPath,
      uri,
      parsedSummary,
      semanticStatus: {
        success: false,
        diagnostics: semanticValidation.diagnostics,
      },
      normalizedRule: null,
      ruleHash: null,
      templateVariables,
      diagnostics: semanticValidation.diagnostics,
    };
  }

  const normalized = normalizeRuleDocument(contractValidation.data);

  parsedSummary.phases.normalization = 'success';

  return {
    displayPath,
    uri,
    parsedSummary,
    semanticStatus: {
      success: true,
      diagnostics: [],
    },
    normalizedRule: normalized.rule,
    ruleHash: normalized.ruleHash,
    templateVariables,
    diagnostics: [],
  };
}

function createInvalidSingleFileState(
  cwd: string,
  inputPath: string,
  diagnostics: Diagnostic[],
): SingleFileCommandState {
  const uri = pathToFileURL(resolve(cwd, inputPath)).href;

  return {
    displayPath: inputPath,
    uri,
    parsedSummary: createParsedSummary(inputPath, uri),
    semanticStatus: {
      success: false,
      diagnostics,
    },
    normalizedRule: null,
    ruleHash: null,
    templateVariables: { ...DEFAULT_TEMPLATE_VARIABLES },
    diagnostics,
  };
}

export function handleValidate(
  target: string,
  format: OutputFormat,
  runtime: Required<CliRuntime>,
): number {
  const resolved = resolveValidateTargets(runtime.cwd, target);

  if (!resolved.success) {
    const failure = resolved as Extract<
      ReturnType<typeof resolveValidateTargets>,
      { success: false }
    >;
    const exitCode = determineExitCode(failure.diagnostics);
    const envelope: ValidateCommandEnvelope = {
      command: 'rules.validate',
      format,
      target,
      matchedFileCount: 0,
      results: [],
      diagnostics: aggregateDiagnostics(failure.diagnostics),
      exitCode: exitCode === 0 ? 1 : exitCode,
    };

    if (format === 'json') {
      runtime.writeStdout(renderJson(envelope));
    } else {
      runtime.writeStderr(formatDiagnosticsForTerminal(envelope.diagnostics));
    }

    return envelope.exitCode;
  }

  const results = resolved.files
    .sort((left, right) => left.localeCompare(right))
    .map((absolutePath) =>
      validateResultForFileSafe(absolutePath, runtime.cwd),
    );
  const diagnostics = aggregateDiagnostics(
    results.flatMap((result) => result.diagnostics),
  );
  const exitCode = determineExitCode(diagnostics);
  const envelope: ValidateCommandEnvelope = {
    command: 'rules.validate',
    format,
    target,
    matchedFileCount: results.length,
    results,
    diagnostics,
    exitCode,
  };

  if (format === 'json') {
    runtime.writeStdout(renderJson(envelope));
  } else {
    runtime.writeStdout(renderValidatePretty(envelope));
  }

  return exitCode;
}

export function handleTest(
  target: string | undefined,
  format: OutputFormat,
  runtime: Required<CliRuntime>,
): number {
  const resolved = resolveTestTargets(runtime.cwd, target);

  if (!resolved.success) {
    const failure = resolved as Extract<
      ReturnType<typeof resolveTestTargets>,
      { success: false }
    >;
    const exitCode = determineExitCode(failure.diagnostics) || 1;
    const envelope: TestCommandEnvelope = {
      command: 'rules.test',
      format,
      target: failure.target,
      matchedFileCount: 0,
      results: [],
      diagnostics: aggregateDiagnostics(failure.diagnostics),
      exitCode,
    };

    if (format === 'json') {
      runtime.writeStdout(renderJson(envelope));
    } else {
      runtime.writeStderr(formatDiagnosticsForTerminal(envelope.diagnostics));
    }

    return exitCode;
  }

  const results = resolved.files
    .sort((left, right) => left.localeCompare(right))
    .map((absolutePath) => {
      const runResult = runRuleSpec(absolutePath);

      return {
        specPath: toDisplayPath(runtime.cwd, absolutePath),
        success: runResult.success,
        diagnostics: runResult.diagnostics,
        run: runResult,
        result: formatRuleSpecRunAsJson(runResult),
      } satisfies TestSpecResult;
    });
  const diagnostics = aggregateDiagnostics(
    results.flatMap((result) => [
      ...result.diagnostics,
      ...result.run.fixtureResults.flatMap(
        (fixtureResult) => fixtureResult.diagnostics,
      ),
    ]),
  );
  const hasFailures = results.some((result) => !result.success);
  const exitCode =
    diagnostics.length > 0
      ? determineExitCode(diagnostics)
      : hasFailures
        ? 1
        : 0;
  const envelope: TestCommandEnvelope = {
    command: 'rules.test',
    format,
    target: resolved.target,
    matchedFileCount: results.length,
    results,
    diagnostics,
    exitCode,
  };

  if (format === 'json') {
    runtime.writeStdout(renderJson(envelope));
  } else {
    runtime.writeStdout(renderTestPretty(envelope));
  }

  return exitCode;
}

export function handleNormalizeOrExplain(
  command: 'normalize' | 'explain',
  inputPath: string,
  format: OutputFormat,
  runtime: Required<CliRuntime>,
): number {
  const resolved = resolveSingleFilePath(runtime.cwd, inputPath);

  if (!resolved.success) {
    const failure = resolved as Extract<
      ReturnType<typeof resolveSingleFilePath>,
      { success: false }
    >;
    const diagnostics = aggregateDiagnostics(failure.diagnostics);
    const exitCode = determineExitCode(diagnostics) || 1;
    const baseState = createInvalidSingleFileState(
      runtime.cwd,
      inputPath,
      diagnostics,
    );
    const envelope =
      command === 'normalize'
        ? ({
            command: 'rules.normalize',
            format,
            file: {
              path: inputPath,
              uri: baseState.uri,
            },
            parsedSummary: baseState.parsedSummary,
            semanticStatus: baseState.semanticStatus,
            normalizedRule: null,
            ruleHash: null,
            diagnostics,
            exitCode,
          } satisfies NormalizeCommandEnvelope)
        : ({
            command: 'rules.explain',
            format,
            file: {
              path: inputPath,
              uri: baseState.uri,
            },
            parsedSummary: baseState.parsedSummary,
            semanticStatus: baseState.semanticStatus,
            normalizedRule: null,
            ruleHash: null,
            templateVariables: baseState.templateVariables,
            diagnostics,
            exitCode,
          } satisfies ExplainCommandEnvelope);

    if (format === 'json') {
      runtime.writeStdout(renderJson(envelope));
    } else {
      runtime.writeStderr(
        command === 'normalize'
          ? renderSingleFilePretty('normalize', baseState)
          : renderSingleFilePretty('explain', baseState),
      );
    }

    return exitCode;
  }

  const state = buildSingleFileState(resolved.absolutePath, runtime.cwd);
  const exitCode = determineExitCode(state.diagnostics);

  if (command === 'normalize') {
    const envelope: NormalizeCommandEnvelope = {
      command: 'rules.normalize',
      format,
      file: {
        path: state.displayPath,
        uri: state.uri,
      },
      parsedSummary: state.parsedSummary,
      semanticStatus: state.semanticStatus,
      normalizedRule: state.normalizedRule,
      ruleHash: state.ruleHash,
      diagnostics: state.diagnostics,
      exitCode,
    };

    if (format === 'json') {
      runtime.writeStdout(renderJson(envelope));
    } else {
      runtime.writeStdout(renderSingleFilePretty('normalize', state));
    }

    return exitCode;
  }

  const envelope: ExplainCommandEnvelope = {
    command: 'rules.explain',
    format,
    file: {
      path: state.displayPath,
      uri: state.uri,
    },
    parsedSummary: state.parsedSummary,
    semanticStatus: state.semanticStatus,
    normalizedRule: state.normalizedRule,
    ruleHash: state.ruleHash,
    templateVariables: state.templateVariables,
    diagnostics: state.diagnostics,
    exitCode,
  };

  if (format === 'json') {
    runtime.writeStdout(renderJson(envelope));
  } else {
    runtime.writeStdout(renderSingleFilePretty('explain', state));
  }

  return exitCode;
}
