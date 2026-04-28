import type { TrackedIdentifierState } from './types';

export interface CollectTrackedIdentifiersOptions {
  text: string;
  assignmentPattern: RegExp;
  isSqlInterpolatedExpression: (
    expression: string,
    sqlInterpolatedIdentifiers: ReadonlySet<string>,
  ) => boolean;
  isTaintedExpression: (
    expression: string,
    taintedIdentifiers: ReadonlySet<string>,
  ) => boolean;
  normalizeIdentifier?: (identifier: string) => string;
  seedSqlInterpolatedIdentifiers?: Iterable<string>;
  seedTaintedIdentifiers?: Iterable<string>;
  stripLineComment?: (line: string) => string;
}

function normalizePattern(pattern: RegExp): RegExp {
  return new RegExp(
    pattern.source,
    pattern.flags.replace(/g/g, ''),
  );
}

export function collectTrackedIdentifiers(
  options: CollectTrackedIdentifiersOptions,
): TrackedIdentifierState {
  const taintedIdentifiers = new Set<string>(options.seedTaintedIdentifiers ?? []);
  const sqlInterpolatedIdentifiers = new Set<string>(
    options.seedSqlInterpolatedIdentifiers ?? [],
  );
  const assignmentPattern = normalizePattern(options.assignmentPattern);
  const normalizeIdentifier = options.normalizeIdentifier ?? ((value) => value);
  const stripLineComment = options.stripLineComment ?? ((line: string) => line);

  for (const rawLine of options.text.split(/\r?\n/u)) {
    const line = stripLineComment(rawLine).trim();

    if (line.length === 0) {
      continue;
    }

    const assignmentMatch = assignmentPattern.exec(line);

    if (!assignmentMatch) {
      continue;
    }

    const identifier = normalizeIdentifier(assignmentMatch[1] ?? '');
    const expression = assignmentMatch[2] ?? '';

    if (
      identifier.length === 0 ||
      expression.length === 0
    ) {
      continue;
    }

    if (
      options.isTaintedExpression(expression, taintedIdentifiers)
    ) {
      taintedIdentifiers.add(identifier);
    }

    if (
      options.isSqlInterpolatedExpression(
        expression,
        sqlInterpolatedIdentifiers,
      )
    ) {
      sqlInterpolatedIdentifiers.add(identifier);
    }
  }

  return {
    taintedIdentifiers,
    sqlInterpolatedIdentifiers,
  };
}
