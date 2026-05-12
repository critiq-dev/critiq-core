import { formatDiagnosticsForTerminal } from '@critiq/core-diagnostics';
import { formatRuleSpecRunForTerminal } from '@critiq/testing-harness';

import {
  type ExplainCommandEnvelope,
  type SingleFileCommandState,
  type TestCommandEnvelope,
  type ValidateCommandEnvelope,
} from '../cli.types';

function formatTemplateVariablesForTerminal(
  templateVariables: ExplainCommandEnvelope['templateVariables'],
): string {
  return Object.entries(templateVariables)
    .map(([field, references]) => {
      if (references.length === 0) {
        return `${field}\n  - none`;
      }

      return [
        field,
        ...references.map(
          (reference) => `  - ${reference.raw} (${reference.expression})`,
        ),
      ].join('\n');
    })
    .join('\n');
}

export function renderHelpMessage(): string {
  return [
    'critiq CLI',
    '',
    'Usage:',
    '  critiq check [target] [--base <git-ref>] [--head <git-ref>] [--format pretty|json]',
    '  critiq audit secrets [target] [--base <git-ref>] [--head <git-ref>] [--format pretty|json]',
    '  critiq audit [--help]',
    '  critiq rules validate <glob> [--format pretty|json]',
    '  critiq rules test [glob] [--format pretty|json]',
    '  critiq rules normalize <file> [--format pretty|json]',
    '  critiq rules explain <file> [--format pretty|json]',
    '  critiq help',
    '',
    'Exit codes:',
    '  0 success',
    '  1 user/input errors or validation diagnostics',
    '  2 internal/runtime errors',
  ].join('\n');
}

export function renderAuditHelpMessage(): string {
  return [
    'critiq audit',
    '',
    'Usage:',
    '  critiq audit secrets [target] [--base <git-ref>] [--head <git-ref>] [--format pretty|json]',
    '',
    'Subcommands:',
    '  secrets   Scan the repository or diff for leaked credentials and high-risk patterns.',
    '',
    'Examples:',
    '  critiq audit secrets .',
    '  critiq audit secrets . --base origin/main --head HEAD',
  ].join('\n');
}

export function renderJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export function renderValidatePretty(
  envelope: ValidateCommandEnvelope,
): string {
  const lines = [
    `Validated ${envelope.matchedFileCount} file(s) for \`${envelope.target}\``,
  ];

  for (const result of envelope.results) {
    lines.push('', result.path);

    if (result.success) {
      lines.push('OK');
      continue;
    }

    lines.push(formatDiagnosticsForTerminal(result.diagnostics));
  }

  lines.push('', `Exit code: ${envelope.exitCode}`);

  return lines.join('\n');
}

export function renderTestPretty(envelope: TestCommandEnvelope): string {
  const lines = [
    `Tested ${envelope.matchedFileCount} spec file(s) for \`${envelope.target}\``,
  ];

  for (const result of envelope.results) {
    lines.push('', formatRuleSpecRunForTerminal(result.run));
  }

  lines.push('', `Exit code: ${envelope.exitCode}`);

  return lines.join('\n');
}

export function renderSingleFilePretty(
  heading: 'normalize' | 'explain',
  state: SingleFileCommandState,
): string {
  const lines = [
    'Parsed Summary',
    `Path: ${state.parsedSummary.path}`,
    `URI: ${state.parsedSummary.uri}`,
    `Rule ID: ${state.parsedSummary.ruleId ?? 'Unavailable'}`,
    `Title: ${state.parsedSummary.title ?? 'Unavailable'}`,
    `Summary: ${state.parsedSummary.summary ?? 'Unavailable'}`,
    `Load: ${state.parsedSummary.phases.load}`,
    `Contract validation: ${state.parsedSummary.phases.contractValidation}`,
    `Semantic validation: ${state.parsedSummary.phases.semanticValidation}`,
    `Normalization: ${state.parsedSummary.phases.normalization}`,
    '',
    'Semantic Status',
  ];

  if (state.semanticStatus.diagnostics.length === 0) {
    lines.push('No diagnostics.');
  } else {
    lines.push(formatDiagnosticsForTerminal(state.semanticStatus.diagnostics));
  }

  lines.push('', 'Normalized Rule');

  if (state.normalizedRule) {
    lines.push(renderJson(state.normalizedRule));
  } else {
    lines.push('Unavailable');
  }

  if (heading === 'explain') {
    lines.push('', 'Inferred Template Variables');
    lines.push(formatTemplateVariablesForTerminal(state.templateVariables));
  }

  return lines.join('\n');
}
