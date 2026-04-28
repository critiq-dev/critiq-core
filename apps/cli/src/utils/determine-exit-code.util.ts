import { type Diagnostic } from '@critiq/core-diagnostics';

export function determineExitCode(diagnostics: readonly Diagnostic[]): number {
  if (
    diagnostics.some(
      (diagnostic) => diagnostic.code === 'runtime.internal.error',
    )
  ) {
    return 2;
  }

  if (diagnostics.some((diagnostic) => diagnostic.severity === 'error')) {
    return 1;
  }

  return 0;
}
