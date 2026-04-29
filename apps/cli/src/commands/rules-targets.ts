import { type Diagnostic } from '@critiq/core-diagnostics';
import {
  createCliInputDiagnostic,
  hasGlobMagic,
  toDisplayPath,
  walkFiles,
} from '@critiq/check-runner';
import { minimatch } from 'minimatch';
import { statSync } from 'node:fs';
import { resolve as resolvePath } from 'node:path';

export function resolveValidateTargets(
  cwd: string,
  target: string,
):
  | { success: true; files: string[] }
  | { success: false; diagnostics: Diagnostic[] } {
  const absoluteCandidate = resolvePath(cwd, target);

  if (!hasGlobMagic(target)) {
    try {
      if (!statSync(absoluteCandidate).isFile()) {
        return {
          success: false,
          diagnostics: [
            createCliInputDiagnostic(
              `Expected a file path for \`${target}\`.`,
            ),
          ],
        };
      }

      return {
        success: true,
        files: [absoluteCandidate],
      };
    } catch {
      return {
        success: false,
        diagnostics: [
          {
            ...createCliInputDiagnostic(`No files matched \`${target}\`.`),
            details: {
              target,
            },
          },
        ],
      };
    }
  }

  try {
    const matches = walkFiles(cwd).filter((absolutePath) =>
      minimatch(toDisplayPath(cwd, absolutePath), target, { dot: true }),
    );

    if (matches.length === 0) {
      return {
        success: false,
        diagnostics: [
          {
            ...createCliInputDiagnostic(`No files matched \`${target}\`.`),
            details: {
              target,
            },
          },
        ],
      };
    }

    return {
      success: true,
      files: matches,
    };
  } catch (error) {
    return {
      success: false,
      diagnostics: [
        {
          code: 'runtime.internal.error',
          severity: 'error',
          message:
            error instanceof Error
              ? error.message
              : 'Unexpected file discovery failure.',
          details: {
            target,
          },
        },
      ],
    };
  }
}

export function resolveTestTargets(
  cwd: string,
  target: string | undefined,
):
  | { success: true; target: string; files: string[] }
  | { success: false; target: string; diagnostics: Diagnostic[] } {
  const resolvedTarget = target ?? '**/*.spec.yaml';
  const resolved = resolveValidateTargets(cwd, resolvedTarget);

  if (!resolved.success) {
    const failure = resolved as Extract<typeof resolved, { success: false }>;

    return {
      success: false,
      target: resolvedTarget,
      diagnostics: failure.diagnostics,
    };
  }

  return {
    success: true,
    target: resolvedTarget,
    files: resolved.files,
  };
}

export function resolveSingleFilePath(
  cwd: string,
  inputPath: string,
):
  | { success: true; absolutePath: string }
  | { success: false; diagnostics: Diagnostic[] } {
  if (hasGlobMagic(inputPath)) {
    return {
      success: false,
      diagnostics: [
        createCliInputDiagnostic(
          `Expected a concrete file path for \`${inputPath}\`, not a glob.`,
        ),
      ],
    };
  }

  return {
    success: true,
    absolutePath: resolvePath(cwd, inputPath),
  };
}
