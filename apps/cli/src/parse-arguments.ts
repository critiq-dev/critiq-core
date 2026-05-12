import { type Diagnostic } from '@critiq/core-diagnostics';

import { type ParsedArguments } from './cli.types';

export function parseArguments(
  args: readonly string[],
): ParsedArguments | Diagnostic {
  const positionals: string[] = [];
  let format: ParsedArguments['format'] = 'pretty';
  let help = false;
  let baseRef: string | undefined;
  let headRef: string | undefined;
  let staged = false;

  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];

    if (value === '--help' || value === 'help') {
      help = true;
      continue;
    }

    if (value.startsWith('--format=')) {
      const nextFormat = value.slice('--format='.length);

      if (
        nextFormat !== 'pretty' &&
        nextFormat !== 'json' &&
        nextFormat !== 'sarif' &&
        nextFormat !== 'html'
      ) {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message: `Unsupported format: ${nextFormat}`,
          details: {
            expected: ['pretty', 'json', 'sarif', 'html'],
            received: nextFormat,
          },
        };
      }

      format = nextFormat;
      continue;
    }

    if (value === '--format') {
      const nextFormat = args[index + 1];

      if (
        nextFormat !== 'pretty' &&
        nextFormat !== 'json' &&
        nextFormat !== 'sarif' &&
        nextFormat !== 'html'
      ) {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message:
            'Expected `--format` to be followed by `pretty`, `json`, `sarif`, or `html`.',
          details: {
            expected: ['pretty', 'json', 'sarif', 'html'],
            received: nextFormat ?? null,
          },
        };
      }

      format = nextFormat;
      index += 1;
      continue;
    }

    if (value.startsWith('--base=')) {
      const nextBaseRef = value.slice('--base='.length);

      if (nextBaseRef.trim().length === 0) {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message: 'Expected `--base` to be followed by a git ref.',
          details: {
            received: nextBaseRef,
          },
        };
      }

      baseRef = nextBaseRef;
      continue;
    }

    if (value === '--base') {
      const nextBaseRef = args[index + 1];

      if (!nextBaseRef || nextBaseRef.startsWith('--')) {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message: 'Expected `--base` to be followed by a git ref.',
          details: {
            received: nextBaseRef ?? null,
          },
        };
      }

      baseRef = nextBaseRef;
      index += 1;
      continue;
    }

    if (value.startsWith('--head=')) {
      const nextHeadRef = value.slice('--head='.length);

      if (nextHeadRef.trim().length === 0) {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message: 'Expected `--head` to be followed by a git ref.',
          details: {
            received: nextHeadRef,
          },
        };
      }

      headRef = nextHeadRef;
      continue;
    }

    if (value === '--head') {
      const nextHeadRef = args[index + 1];

      if (!nextHeadRef || nextHeadRef.startsWith('--')) {
        return {
          code: 'cli.argument.invalid',
          severity: 'error',
          message: 'Expected `--head` to be followed by a git ref.',
          details: {
            received: nextHeadRef ?? null,
          },
        };
      }

      headRef = nextHeadRef;
      index += 1;
      continue;
    }

    if (value === '--staged') {
      staged = true;
      continue;
    }

    if (value.startsWith('--')) {
      return {
        code: 'cli.argument.invalid',
        severity: 'error',
        message: `Unknown option: ${value}`,
      };
    }

    positionals.push(value);
  }

  if (staged && (baseRef !== undefined || headRef !== undefined)) {
    return {
      code: 'cli.argument.invalid',
      severity: 'error',
      message: 'Cannot combine `--staged` with `--base` / `--head`.',
    };
  }

  return {
    positionals,
    format,
    help,
    baseRef,
    headRef,
    staged,
  };
}
