#!/usr/bin/env node

import { formatDiagnosticsForTerminal } from '@critiq/core-diagnostics';
import { resolve } from 'node:path';

import { resolveRuntime } from './cli-runtime';
import { handleCheck } from './commands/check.command';
import {
  handleNormalizeOrExplain,
  handleTest,
  handleValidate,
} from './commands/rules.command';
import { parseArguments } from './parse-arguments';
import { renderHelpMessage } from './rendering/rules.rendering';
import { type CliRuntime } from './cli.types';
import { isLegacyRulesArgument } from './utils/is-legacy-rules-argument.util';

/**
 * Runs the Critiq CLI and returns a stable exit code.
 */
export function runCli(
  args: readonly string[] = process.argv.slice(2),
  runtime: CliRuntime = {},
): number {
  const resolvedRuntime = resolveRuntime(runtime);

  if (args.length === 0 || args[0] === 'help' || args[0] === '--help') {
    resolvedRuntime.writeStdout(renderHelpMessage());
    return 0;
  }

  if (args[0] === 'check') {
    const parsed = parseArguments(args.slice(1));

    if ('code' in parsed) {
      resolvedRuntime.writeStderr(formatDiagnosticsForTerminal([parsed]));
      return 1;
    }

    if (parsed.help) {
      resolvedRuntime.writeStdout(renderHelpMessage());
      return 0;
    }

    if (parsed.positionals.length > 1) {
      resolvedRuntime.writeStderr(
        'The `check` command no longer accepts a rules glob. Create `.critiq/config.yaml` and run `critiq check .`.',
      );
      return 1;
    }

    if (
      parsed.positionals.length === 1 &&
      isLegacyRulesArgument(parsed.positionals[0])
    ) {
      resolvedRuntime.writeStderr(
        'The `check` command no longer accepts a rules glob. Create `.critiq/config.yaml` and run `critiq check .`.',
      );
      return 1;
    }

    return handleCheck(
      parsed.positionals[0],
      parsed.format,
      resolvedRuntime,
      parsed.baseRef,
      parsed.headRef,
    );
  }

  if (args[0] !== 'rules') {
    resolvedRuntime.writeStderr(`Unknown command: ${args[0]}`);
    resolvedRuntime.writeStdout(renderHelpMessage());
    return 1;
  }

  const subcommand = args[1];
  const parsed = parseArguments(args.slice(2));

  if (subcommand === 'help' || subcommand === '--help') {
    resolvedRuntime.writeStdout(renderHelpMessage());
    return 0;
  }

  if ('code' in parsed) {
    resolvedRuntime.writeStderr(formatDiagnosticsForTerminal([parsed]));
    return 1;
  }

  if (parsed.help || !subcommand) {
    resolvedRuntime.writeStdout(renderHelpMessage());
    return 0;
  }

  if (subcommand === 'validate') {
    if (parsed.positionals.length !== 1) {
      resolvedRuntime.writeStderr(
        'Expected `critiq rules validate <glob>` with exactly one target.',
      );
      return 1;
    }

    return handleValidate(
      parsed.positionals[0],
      parsed.format,
      resolvedRuntime,
    );
  }

  if (subcommand === 'test') {
    if (parsed.positionals.length > 1) {
      resolvedRuntime.writeStderr(
        'Expected `critiq rules test [glob]` with zero or one target.',
      );
      return 1;
    }

    return handleTest(parsed.positionals[0], parsed.format, resolvedRuntime);
  }

  if (subcommand === 'normalize') {
    if (parsed.positionals.length !== 1) {
      resolvedRuntime.writeStderr(
        'Expected `critiq rules normalize <file>` with exactly one file.',
      );
      return 1;
    }

    return handleNormalizeOrExplain(
      'normalize',
      parsed.positionals[0],
      parsed.format,
      resolvedRuntime,
    );
  }

  if (subcommand === 'explain') {
    if (parsed.positionals.length !== 1) {
      resolvedRuntime.writeStderr(
        'Expected `critiq rules explain <file>` with exactly one file.',
      );
      return 1;
    }

    return handleNormalizeOrExplain(
      'explain',
      parsed.positionals[0],
      parsed.format,
      resolvedRuntime,
    );
  }

  resolvedRuntime.writeStderr(`Unknown command: rules ${subcommand}`);
  resolvedRuntime.writeStdout(renderHelpMessage());
  return 1;
}

function isCliEntrypoint(): boolean {
  if (require.main === module) {
    return true;
  }

  const mainFilename = require.main?.filename;

  if (!mainFilename) {
    return false;
  }

  // Nx emits a root wrapper at dist/apps/cli/main.js that requires the real
  // compiled CLI module from dist/apps/cli/apps/cli/src/main.js.
  return mainFilename === resolve(__dirname, '..', '..', '..', 'main.js');
}

if (isCliEntrypoint()) {
  process.exitCode = runCli();
}

export type { CliRuntime } from './cli.types';
