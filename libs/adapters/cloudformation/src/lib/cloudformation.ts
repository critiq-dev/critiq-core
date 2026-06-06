import { buildAnalyzedFileWithFacts } from '@critiq/adapter-shared';
import { createDiagnostic, type Diagnostic } from '@critiq/core-diagnostics';
import type { AnalyzedFile } from '@critiq/core-rules-engine';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, extname, join } from 'node:path';

import { collectCfnLintFacts } from './collect-cfn-lint-facts.util';
import type { CfnLintRunner } from './cfn-lint.types';
import {
  isCloudFormationTemplate,
  looksLikeCloudFormationPath,
} from './is-cloudformation-template.util';
import { parseCfnLintJson } from './parse-cfn-lint-json.util';
import { runCfnLint } from './run-cfn-lint.util';

export type CloudFormationAnalysisResult =
  | { success: true; data: AnalyzedFile; diagnostics?: Diagnostic[] }
  | { success: false; diagnostics: Diagnostic[] };

const SUPPORTED_EXTENSIONS = ['.yaml', '.yml', '.json'] as const;

function templateExtensionForPath(path: string): string {
  const extension = extname(path).toLowerCase();

  if (
    extension === '.yaml' ||
    extension === '.yml' ||
    extension === '.json'
  ) {
    return extension;
  }

  return '.yaml';
}

function createMissingCfnLintDiagnostic(path: string): Diagnostic {
  return createDiagnostic({
    code: 'adapter.cloudformation.cfn-lint-missing',
    message:
      'The `cfn-lint` executable was not found on PATH. Install cfn-lint to analyze CloudFormation templates.',
    severity: 'warning',
    details: {
      path,
    },
  });
}

function createCfnLintFailureDiagnostic(
  path: string,
  stderr: string,
): Diagnostic {
  return createDiagnostic({
    code: 'adapter.cloudformation.cfn-lint-failed',
    message: `cfn-lint failed while analyzing \`${path}\`.`,
    severity: 'warning',
    details: {
      path,
      stderr,
    },
  });
}

/**
 * Analyzes a CloudFormation template by invoking cfn-lint and normalizing findings.
 */
export function analyzeCloudFormationFile(
  path: string,
  text: string,
  options: { runCfnLint?: CfnLintRunner } = {},
): CloudFormationAnalysisResult {
  if (!isCloudFormationTemplate(path, text)) {
    return {
      success: true,
      data: buildAnalyzedFileWithFacts(path, 'cloudformation', text, []),
    };
  }

  const runner = options.runCfnLint ?? runCfnLint;
  const tempDirectory = mkdtempSync(join(tmpdir(), 'critiq-cfn-'));
  const tempPath = join(
    tempDirectory,
    `${basename(path, extname(path)) || 'template'}${templateExtensionForPath(path)}`,
  );

  try {
    writeFileSync(tempPath, text, 'utf8');
    const lintResult = runner(tempPath);

    if (lintResult.errorCode === 'ENOENT') {
      return {
        success: true,
        data: buildAnalyzedFileWithFacts(path, 'cloudformation', text, []),
        diagnostics: [createMissingCfnLintDiagnostic(path)],
      };
    }

    if (!lintResult.ok && !lintResult.stdout.trim()) {
      return {
        success: true,
        data: buildAnalyzedFileWithFacts(path, 'cloudformation', text, []),
        diagnostics: [
          createCfnLintFailureDiagnostic(path, lintResult.stderr),
        ],
      };
    }

    const findings = parseCfnLintJson(lintResult.stdout);
    const facts = collectCfnLintFacts(text, findings);

    return {
      success: true,
      data: buildAnalyzedFileWithFacts(path, 'cloudformation', text, facts),
    };
  } finally {
    rmSync(tempDirectory, { recursive: true, force: true });
  }
}

export const cloudformationSourceAdapter = {
  packageName: '@critiq/adapter-cloudformation',
  supportedExtensions: SUPPORTED_EXTENSIONS,
  supportedLanguages: ['cloudformation'] as const,
  canHandlePath: looksLikeCloudFormationPath,
  canHandle: isCloudFormationTemplate,
  analyze: analyzeCloudFormationFile,
} as const;
