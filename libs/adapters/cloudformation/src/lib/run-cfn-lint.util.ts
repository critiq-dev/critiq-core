import { execFileSync } from 'node:child_process';

import type { CfnLintRunResult } from './cfn-lint.types';

function readExecOutput(value: unknown): string {
  if (typeof value === 'string') {
    return value;
  }

  if (Buffer.isBuffer(value)) {
    return value.toString('utf8');
  }

  return '';
}

/**
 * Runs `cfn-lint -f json` against a template file on disk.
 */
export function runCfnLint(filePath: string): CfnLintRunResult {
  try {
    const stdout = execFileSync('cfn-lint', ['-f', 'json', filePath], {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });

    return {
      ok: true,
      stdout,
      stderr: '',
      exitCode: 0,
    };
  } catch (error) {
    if (
      typeof error === 'object' &&
      error !== null &&
      'code' in error &&
      error.code === 'ENOENT'
    ) {
      return {
        ok: false,
        stdout: '',
        stderr: '',
        exitCode: -1,
        errorCode: 'ENOENT',
      };
    }

    if (typeof error === 'object' && error !== null && 'stdout' in error) {
      return {
        ok: true,
        stdout: readExecOutput(error.stdout),
        stderr: readExecOutput(
          'stderr' in error ? error.stderr : undefined,
        ),
        exitCode:
          'status' in error && typeof error.status === 'number'
            ? error.status
            : 1,
      };
    }

    const message =
      error instanceof Error ? error.message : 'Unexpected cfn-lint failure.';

    return {
      ok: false,
      stdout: '',
      stderr: message,
      exitCode: 1,
    };
  }
}
