import type { ObservedFact } from '@critiq/core-rules-engine';

import { escapeRegExp, findAllMatches, findMatchingDelimiter } from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const PHP_CORRECTNESS_FACT_KINDS = {
  duplicateArrayKey: 'php.correctness.duplicate-array-key',
  switchMultipleDefault: 'php.correctness.switch-multiple-default',
  errorSuppressionOperator: 'php.correctness.error-suppression-operator',
  unreachableAfterReturn: 'php.correctness.unreachable-after-return',
  nullsafeReturnedByReference: 'php.correctness.nullsafe-returned-by-reference',
  emptyArrayLiteralSlot: 'php.correctness.empty-array-literal-slot',
  emptyBracketArrayAccess: 'php.correctness.empty-bracket-array-access',
  deprecatedUnsetCast: 'php.correctness.deprecated-unset-cast',
  duplicateDeclaration: 'php.correctness.duplicate-declaration',
  nestedFunctionDeclaration: 'php.correctness.nested-function-declaration',
  breakContinueOutsideLoop: 'php.correctness.break-continue-outside-loop',
  abstractMethodOutsideAbstractClass:
    'php.correctness.abstract-method-outside-abstract-class',
  uselessUnset: 'php.correctness.useless-unset',
  invalidRegexLiteral: 'php.correctness.invalid-regex-literal',
  todoFixmeMarker: 'php.correctness.todo-fixme-marker',
  selfAssignment: 'php.correctness.self-assignment',
  defaultParameterNotLast: 'php.correctness.default-parameter-not-last',
  emptyFunctionBody: 'php.correctness.empty-function-body',
  unknownMagicMethod: 'php.correctness.unknown-magic-method',
  caseInsensitiveDefine: 'php.correctness.case-insensitive-define',
  deprecatedFilterConstant: 'php.correctness.deprecated-filter-constant',
  emptyCodeBlock: 'php.correctness.empty-code-block',
  deprecatedLibxmlEntityLoader: 'php.correctness.deprecated-libxml-entity-loader',
  redundantStringCastConcat: 'php.correctness.redundant-string-cast-concat',
  missingMemberVisibility: 'php.correctness.missing-member-visibility',
  functionComparison: 'php.correctness.function-comparison',
  uselessPostIncrement: 'php.correctness.useless-post-increment',
  nestedSwitch: 'php.correctness.nested-switch',
  invalidCookieOptions: 'php.correctness.invalid-cookie-options',
  missingReturnStatement: 'php.correctness.missing-return-statement',
  uninitializedTypedProperty: 'php.correctness.uninitialized-typed-property',
  throwNonException: 'php.correctness.throw-non-exception',
  unusedConstructorParameter:
    'php.correctness.unused-constructor-parameter',
  echoInvalidValue: 'php.correctness.echo-invalid-value',
  printInvalidValue: 'php.correctness.print-invalid-value',
  invalidStringInterpolationType:
    'php.correctness.invalid-string-interpolation-type',
  undefinedStaticProperty:
    'php.correctness.undefined-static-property',
} as const;

const PHP_VALID_MAGIC_METHODS = new Set([
  '__construct',
  '__destruct',
  '__call',
  '__callStatic',
  '__get',
  '__set',
  '__isset',
  '__unset',
  '__sleep',
  '__wakeup',
  '__serialize',
  '__unserialize',
  '__toString',
  '__invoke',
  '__set_state',
  '__clone',
  '__debugInfo',
]);

const PHP_VALID_COOKIE_OPTION_KEYS = new Set([
  'expires',
  'path',
  'domain',
  'secure',
  'httponly',
  'samesite',
]);

const PHP_DEPRECATED_FILTER_CONSTANTS =
  /\bFILTER_(?:SANITIZE_STRING|SANITIZE_MAGIC_QUOTES|FLAG_ALLOW_THOUSAND)\b/gu;

export interface CollectPhpCorrectnessFactsOptions {
  text: string;
  detector: string;
}

export function collectPhpCorrectnessFacts(
  options: CollectPhpCorrectnessFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return dedupeFacts([
    ...collectDuplicateArrayKeyFacts(text, detector),
    ...collectSwitchMultipleDefaultFacts(text, detector),
    ...collectErrorSuppressionOperatorFacts(text, detector),
    ...collectUnreachableAfterReturnFacts(text, detector),
    ...collectNullsafeReturnedByReferenceFacts(text, detector),
    ...collectEmptyArrayLiteralSlotFacts(text, detector),
    ...collectEmptyBracketArrayAccessFacts(text, detector),
    ...collectDeprecatedUnsetCastFacts(text, detector),
    ...collectDuplicateDeclarationFacts(text, detector),
    ...collectNestedFunctionDeclarationFacts(text, detector),
    ...collectBreakContinueOutsideLoopFacts(text, detector),
    ...collectAbstractMethodOutsideAbstractClassFacts(text, detector),
    ...collectUselessUnsetFacts(text, detector),
    ...collectInvalidRegexLiteralFacts(text, detector),
    ...collectTodoFixmeMarkerFacts(text, detector),
    ...collectSelfAssignmentFacts(text, detector),
    ...collectDefaultParameterNotLastFacts(text, detector),
    ...collectEmptyFunctionBodyFacts(text, detector),
    ...collectUnknownMagicMethodFacts(text, detector),
    ...collectCaseInsensitiveDefineFacts(text, detector),
    ...collectDeprecatedFilterConstantFacts(text, detector),
    ...collectEmptyCodeBlockFacts(text, detector),
    ...collectDeprecatedLibxmlEntityLoaderFacts(text, detector),
    ...collectRedundantStringCastConcatFacts(text, detector),
    ...collectMissingMemberVisibilityFacts(text, detector),
    ...collectFunctionComparisonFacts(text, detector),
    ...collectUselessPostIncrementFacts(text, detector),
    ...collectNestedSwitchFacts(text, detector),
    ...collectInvalidCookieOptionsFacts(text, detector),
    ...collectMissingReturnStatementFacts(text, detector),
    ...collectUninitializedTypedPropertyFacts(text, detector),
    ...collectThrowNonExceptionFacts(text, detector),
    ...collectUnusedConstructorParameterFacts(text, detector),
    ...collectEchoInvalidValueFacts(text, detector),
    ...collectPrintInvalidValueFacts(text, detector),
    ...collectInvalidStringInterpolationTypeFacts(text, detector),
    ...collectUndefinedStaticPropertyFacts(text, detector),
  ]);
}

function collectDuplicateArrayKeyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.duplicateArrayKey;
  const findings: ObservedFact[] = [];

  for (const literal of collectPhpArrayLiteralRanges(text)) {
    const seen = new Set<string>();
    const entries = splitTopLevelEntries(literal.content);

    for (const entry of entries) {
      const key = extractStaticArrayKey(entry.text);

      if (!key) {
        continue;
      }

      if (seen.has(key.normalized)) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: literal.startOffset + entry.startOffset,
            endOffset:
              literal.startOffset + entry.startOffset + key.raw.length,
            text: key.raw,
          }),
        );
        continue;
      }

      seen.add(key.normalized);
    }
  }

  return findings;
}

interface ArrayLiteralRange {
  startOffset: number;
  endOffset: number;
  content: string;
}

function collectPhpArrayLiteralRanges(text: string): ArrayLiteralRange[] {
  const ranges: ArrayLiteralRange[] = [];

  const arrayCallPattern = /\barray\s*\(/gu;

  for (const match of findAllMatches(text, arrayCallPattern)) {
    const openParen = match.endOffset - 1;
    const closeParen = findMatchingDelimiter(text, openParen, '(', ')');

    if (closeParen < 0) {
      continue;
    }

    const content = text.slice(openParen + 1, closeParen);

    if (!hasTopLevelArrow(content)) {
      continue;
    }

    ranges.push({
      startOffset: match.startOffset,
      endOffset: closeParen + 1,
      content,
    });
  }

  const stack: number[] = [];

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];

    if (char === '[') {
      stack.push(index);
      continue;
    }

    if (char !== ']' || stack.length === 0) {
      continue;
    }

    const start = stack.pop();

    if (start === undefined) {
      continue;
    }

    const content = text.slice(start + 1, index);

    if (!hasTopLevelArrow(content)) {
      continue;
    }

    ranges.push({
      startOffset: start,
      endOffset: index + 1,
      content,
    });
  }

  return ranges;
}

function hasTopLevelArrow(source: string): boolean {
  let depthParen = 0;
  let depthBracket = 0;
  let depthBrace = 0;

  for (let index = 0; index < source.length - 1; index += 1) {
    const char = source[index];
    const next = source[index + 1];

    if (char === '(') {
      depthParen += 1;
      continue;
    }
    if (char === ')') {
      depthParen = Math.max(0, depthParen - 1);
      continue;
    }
    if (char === '[') {
      depthBracket += 1;
      continue;
    }
    if (char === ']') {
      depthBracket = Math.max(0, depthBracket - 1);
      continue;
    }
    if (char === '{') {
      depthBrace += 1;
      continue;
    }
    if (char === '}') {
      depthBrace = Math.max(0, depthBrace - 1);
      continue;
    }

    if (
      char === '=' &&
      next === '>' &&
      depthParen === 0 &&
      depthBracket === 0 &&
      depthBrace === 0
    ) {
      return true;
    }
  }

  return false;
}

interface TopLevelEntry {
  text: string;
  startOffset: number;
}

function splitTopLevelEntries(source: string): TopLevelEntry[] {
  const entries: TopLevelEntry[] = [];
  let start = 0;
  let depthParen = 0;
  let depthBracket = 0;
  let depthBrace = 0;

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];

    if (char === '(') {
      depthParen += 1;
      continue;
    }
    if (char === ')') {
      depthParen = Math.max(0, depthParen - 1);
      continue;
    }
    if (char === '[') {
      depthBracket += 1;
      continue;
    }
    if (char === ']') {
      depthBracket = Math.max(0, depthBracket - 1);
      continue;
    }
    if (char === '{') {
      depthBrace += 1;
      continue;
    }
    if (char === '}') {
      depthBrace = Math.max(0, depthBrace - 1);
      continue;
    }

    if (
      char === ',' &&
      depthParen === 0 &&
      depthBracket === 0 &&
      depthBrace === 0
    ) {
      const textValue = source.slice(start, index).trim();

      if (textValue.length > 0) {
        const leftTrimmed = source.slice(start, index).match(/^\s*/u)?.[0].length ?? 0;
        entries.push({
          text: textValue,
          startOffset: start + leftTrimmed,
        });
      }

      start = index + 1;
    }
  }

  const last = source.slice(start).trim();

  if (last.length > 0) {
    const leftTrimmed = source.slice(start).match(/^\s*/u)?.[0].length ?? 0;
    entries.push({
      text: last,
      startOffset: start + leftTrimmed,
    });
  }

  return entries;
}

interface StaticArrayKey {
  raw: string;
  normalized: string;
}

function extractStaticArrayKey(entry: string): StaticArrayKey | undefined {
  if (entry.startsWith('...')) {
    return undefined;
  }

  let depthParen = 0;
  let depthBracket = 0;
  let depthBrace = 0;
  let separatorIndex = -1;

  for (let index = 0; index < entry.length - 1; index += 1) {
    const char = entry[index];
    const next = entry[index + 1];

    if (char === '(') {
      depthParen += 1;
      continue;
    }
    if (char === ')') {
      depthParen = Math.max(0, depthParen - 1);
      continue;
    }
    if (char === '[') {
      depthBracket += 1;
      continue;
    }
    if (char === ']') {
      depthBracket = Math.max(0, depthBracket - 1);
      continue;
    }
    if (char === '{') {
      depthBrace += 1;
      continue;
    }
    if (char === '}') {
      depthBrace = Math.max(0, depthBrace - 1);
      continue;
    }

    if (
      char === '=' &&
      next === '>' &&
      depthParen === 0 &&
      depthBracket === 0 &&
      depthBrace === 0
    ) {
      separatorIndex = index;
      break;
    }
  }

  if (separatorIndex < 0) {
    return undefined;
  }

  const keyText = entry.slice(0, separatorIndex).trim();

  if (/^["'][\s\S]*["']$/u.test(keyText)) {
    return {
      raw: keyText,
      normalized: keyText.slice(1, -1),
    };
  }

  if (/^-?\d+$/u.test(keyText)) {
    return {
      raw: keyText,
      normalized: keyText,
    };
  }

  if (/^[A-Za-z_][A-Za-z0-9_]*$/u.test(keyText)) {
    return {
      raw: keyText,
      normalized: keyText,
    };
  }

  return undefined;
}

function collectSwitchMultipleDefaultFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.switchMultipleDefault;
  const findings: ObservedFact[] = [];
  const switchPattern = /\bswitch\s*\(/gu;

  for (const switchMatch of findAllMatches(text, switchPattern)) {
    const openBrace = findSwitchOpenBrace(text, switchMatch.endOffset);

    if (openBrace < 0) {
      continue;
    }

    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');

    if (closeBrace < 0) {
      continue;
    }

    const body = text.slice(openBrace + 1, closeBrace);
    const defaultPattern = /^\s*default\s*:/gmu;
    let defaultCount = 0;

    for (const defaultMatch of body.matchAll(defaultPattern)) {
      const matchIndex = defaultMatch.index ?? 0;

      if (!isTopLevelSwitchDefault(body, matchIndex)) {
        continue;
      }

      defaultCount += 1;

      if (defaultCount > 1) {
        const absoluteStart = openBrace + 1 + matchIndex;
        const absoluteEnd = absoluteStart + defaultMatch[0].length;

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteEnd,
            text: defaultMatch[0].trim(),
          }),
        );
      }
    }
  }

  return findings;
}

function findSwitchOpenBrace(text: string, fromOffset: number): number {
  let depth = 1;

  for (let index = fromOffset; index < text.length; index += 1) {
    const char = text[index];

    if (char === '(') {
      depth += 1;
      continue;
    }

    if (char === ')') {
      depth -= 1;
      continue;
    }

    if (char === '{' && depth === 0) {
      return index;
    }

    if (char === '\n' && depth === 0) {
      return -1;
    }
  }

  return -1;
}

function isTopLevelSwitchDefault(body: string, matchIndex: number): boolean {
  let depthBrace = 0;

  for (let index = 0; index < matchIndex; index += 1) {
    const char = body[index];

    if (char === '{') {
      depthBrace += 1;
      continue;
    }

    if (char === '}') {
      depthBrace = Math.max(0, depthBrace - 1);
    }
  }

  return depthBrace === 0;
}

function collectErrorSuppressionOperatorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.errorSuppressionOperator,
    appliesTo: 'block',
    pattern: /(?<![@\w])@(?=\s*(?:\$|[A-Za-z_(]|new\s))/gu,
  });
}

function collectUnreachableAfterReturnFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.unreachableAfterReturn;
  const findings: ObservedFact[] = [];
  const lines = text.split(/\r?\n/u);
  let offset = 0;
  let braceDepth = 0;
  let unreachableDepth: number | undefined;

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    const trimmed = line.trim();
    const lineStart = offset;
    const lineEnd = offset + line.length;

    if (unreachableDepth !== undefined && trimmed.length > 0) {
      const isClosingBraceOnly = trimmed === '}';
      const isComment =
        trimmed.startsWith('//') ||
        trimmed.startsWith('#') ||
        trimmed.startsWith('/*') ||
        trimmed.startsWith('*');

      if (
        !isClosingBraceOnly &&
        !isComment &&
        braceDepth >= unreachableDepth
      ) {
        const contentStart =
          lineStart + (line.length - line.trimStart().length);
        const contentEnd = lineEnd;

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: contentStart,
            endOffset: contentEnd,
            text: line.trimEnd(),
          }),
        );
      }
    }

    const terminalOnLine =
      /\b(?:return|throw)\b/u.test(line) && /;[\s]*$/u.test(trimmed);

    for (let index = 0; index < line.length; index += 1) {
      const char = line[index];

      if (char === '{') {
        braceDepth += 1;
      } else if (char === '}') {
        braceDepth = Math.max(0, braceDepth - 1);

        if (
          unreachableDepth !== undefined &&
          braceDepth < unreachableDepth
        ) {
          unreachableDepth = undefined;
        }
      }
    }

    if (terminalOnLine) {
      unreachableDepth = braceDepth;
    } else if (
      unreachableDepth !== undefined &&
      braceDepth < unreachableDepth
    ) {
      unreachableDepth = undefined;
    }

    offset = lineEnd;

    if (lineIndex < lines.length - 1) {
      const newline = text.slice(offset).match(/^(\r?\n)/u)?.[1] ?? '\n';
      offset += newline.length;
    }
  }

  return findings;
}

function collectNullsafeReturnedByReferenceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.nullsafeReturnedByReference,
    appliesTo: 'block',
    pattern:
      /\b(?:static\s+)?fn\s*&\s*\([^)]*\)\s*=>\s*[^;{}\n]*\?->/gu,
  });
}

function collectEmptyArrayLiteralSlotFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.emptyArrayLiteralSlot;
  const findings: ObservedFact[] = [];

  for (const literal of collectAllPhpArrayLiteralRanges(text)) {
    for (const match of findAllMatches(literal.content, /,\s*,|\[\s*,/gu)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: literal.startOffset + 1 + match.startOffset,
          endOffset: literal.startOffset + 1 + match.endOffset,
          text: match.matchedText.trim() || ',',
        }),
      );
    }
  }

  return dedupeFacts(findings);
}

function collectAllPhpArrayLiteralRanges(text: string): ArrayLiteralRange[] {
  const ranges: ArrayLiteralRange[] = [];

  const arrayCallPattern = /\barray\s*\(/gu;

  for (const match of findAllMatches(text, arrayCallPattern)) {
    const openParen = match.endOffset - 1;
    const closeParen = findMatchingDelimiter(text, openParen, '(', ')');

    if (closeParen < 0) {
      continue;
    }

    ranges.push({
      startOffset: match.startOffset,
      endOffset: closeParen + 1,
      content: text.slice(openParen + 1, closeParen),
    });
  }

  const stack: number[] = [];

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];

    if (char === '[') {
      stack.push(index);
      continue;
    }

    if (char !== ']' || stack.length === 0) {
      continue;
    }

    const start = stack.pop();

    if (start === undefined) {
      continue;
    }

    ranges.push({
      startOffset: start,
      endOffset: index + 1,
      content: text.slice(start + 1, index),
    });
  }

  return ranges;
}

function collectEmptyBracketArrayAccessFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.emptyBracketArrayAccess,
    appliesTo: 'block',
    pattern: /\$\w+\[\s*\](?!\s*=)/gu,
  });
}

function collectDeprecatedUnsetCastFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.deprecatedUnsetCast,
    appliesTo: 'block',
    pattern: /\(unset\)/gu,
  });
}

function collectDuplicateDeclarationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.duplicateDeclaration;
  const findings: ObservedFact[] = [];
  const seenFunctions = new Map<string, number>();
  const seenClasses = new Map<string, number>();

  for (const match of findAllMatches(
    text,
    /\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu,
  )) {
    const name = /function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/u.exec(
      match.matchedText,
    )?.[1];

    if (!name || !isTopLevelDeclaration(text, match.startOffset)) {
      continue;
    }

    if (seenFunctions.has(name)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: match.matchedText,
        }),
      );
      continue;
    }

    seenFunctions.set(name, match.startOffset);
  }

  for (const match of findAllMatches(
    text,
    /\b(?:class|interface|trait|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\b/gu,
  )) {
    const name =
      /(?:class|interface|trait|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(
        match.matchedText,
      )?.[1];

    if (!name || !isTopLevelDeclaration(text, match.startOffset)) {
      continue;
    }

    if (seenClasses.has(name)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: match.matchedText,
        }),
      );
      continue;
    }

    seenClasses.set(name, match.startOffset);
  }

  return findings;
}

function isTopLevelDeclaration(text: string, offset: number): boolean {
  let braceDepth = 0;

  for (let index = 0; index < offset; index += 1) {
    const char = text[index];

    if (char === '{') {
      braceDepth += 1;
      continue;
    }

    if (char === '}') {
      braceDepth = Math.max(0, braceDepth - 1);
    }
  }

  return braceDepth === 0;
}

function collectNestedFunctionDeclarationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.nestedFunctionDeclaration;
  const findings: ObservedFact[] = [];

  for (const match of findAllMatches(
    text,
    /\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu,
  )) {
    if (!isInsideFunctionBody(text, match.startOffset)) {
      continue;
    }

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
      }),
    );
  }

  return findings;
}

function isInsideFunctionBody(text: string, offset: number): boolean {
  const stack: Array<'class' | 'function'> = [];
  let index = 0;

  while (index < offset) {
    index = skipPhpTrivia(text, index);

    if (index >= offset) {
      break;
    }

    const remaining = text.slice(index);

    if (/^\bfunction\s+[A-Za-z_][\w]*\s*\(/u.test(remaining)) {
      const openBrace = findNextControlOpenBrace(text, index);

      if (openBrace >= 0 && openBrace < offset) {
        stack.push('function');
        index = openBrace + 1;
        continue;
      }
    }

    if (/^\b(?:class|trait|enum)\s+[A-Za-z_]/u.test(remaining)) {
      const openBrace = findNextControlOpenBrace(text, index);

      if (openBrace >= 0 && openBrace < offset) {
        stack.push('class');
        index = openBrace + 1;
        continue;
      }
    }

    const char = text[index];

    if (char === '{') {
      index += 1;
      continue;
    }

    if (char === '}') {
      stack.pop();
      index += 1;
      continue;
    }

    index += 1;
  }

  return stack[stack.length - 1] === 'function';
}

function collectBreakContinueOutsideLoopFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.breakContinueOutsideLoop;
  const findings: ObservedFact[] = [];
  const controlPattern = /\b(?:break|continue)\b(?:\s+\d+\s*)?;/gu;

  for (const match of findAllMatches(text, controlPattern)) {
    const keyword = /\b(break|continue)\b/u.exec(match.matchedText)?.[1];

    if (!keyword) {
      continue;
    }

    const context = getControlFlowContext(text, match.startOffset);

    if (keyword === 'continue' && context.loopDepth === 0) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: match.matchedText,
        }),
      );
      continue;
    }

    if (
      keyword === 'break' &&
      context.loopDepth === 0 &&
      context.switchDepth === 0
    ) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: match.matchedText,
        }),
      );
    }
  }

  return findings;
}

interface ControlFlowContext {
  loopDepth: number;
  switchDepth: number;
}

function getControlFlowContext(
  text: string,
  offset: number,
): ControlFlowContext {
  const stack: Array<'loop' | 'switch'> = [];
  let index = 0;

  while (index < offset) {
    index = skipPhpTrivia(text, index);

    if (index >= offset) {
      break;
    }

    const remaining = text.slice(index);

    if (/^\b(?:for|while|foreach|do)\b/u.test(remaining)) {
      const openBrace = findNextControlOpenBrace(text, index);

      if (openBrace >= 0 && openBrace < offset) {
        stack.push('loop');
        index = openBrace + 1;
        continue;
      }
    }

    if (/^\bswitch\b/u.test(remaining)) {
      const openBrace = findNextControlOpenBrace(text, index);

      if (openBrace >= 0 && openBrace < offset) {
        stack.push('switch');
        index = openBrace + 1;
        continue;
      }
    }

    const char = text[index];

    if (char === '{') {
      index += 1;
      continue;
    }

    if (char === '}') {
      stack.pop();
      index += 1;
      continue;
    }

    index += 1;
  }

  let loopDepth = 0;
  let switchDepth = 0;

  for (const frame of stack) {
    if (frame === 'loop') {
      loopDepth += 1;
    } else {
      switchDepth += 1;
    }
  }

  return { loopDepth, switchDepth };
}

function skipPhpTrivia(text: string, index: number): number {
  const remaining = text.slice(index);

  if (remaining.startsWith('//') || remaining.startsWith('#')) {
    const nextLine = remaining.search(/\r?\n/u);
    return nextLine < 0 ? text.length : index + nextLine + 1;
  }

  if (remaining.startsWith('/*')) {
    const end = remaining.indexOf('*/');
    return end < 0 ? text.length : index + end + 2;
  }

  const quote = remaining[0];

  if (quote === '"' || quote === "'") {
    return skipQuotedPhpString(text, index, quote);
  }

  return index;
}

function skipQuotedPhpString(
  text: string,
  index: number,
  quote: string,
): number {
  let cursor = index + 1;

  while (cursor < text.length) {
    const char = text[cursor];

    if (char === '\\') {
      cursor += 2;
      continue;
    }

    if (char === quote) {
      return cursor + 1;
    }

    cursor += 1;
  }

  return text.length;
}

function findNextControlOpenBrace(text: string, fromOffset: number): number {
  let depth = 0;
  let index = fromOffset;

  while (index < text.length) {
    index = skipPhpTrivia(text, index);

    if (index >= text.length) {
      return -1;
    }

    const char = text[index];

    if (char === '(') {
      depth += 1;
      index += 1;
      continue;
    }

    if (char === ')') {
      depth = Math.max(0, depth - 1);
      index += 1;
      continue;
    }

    if (char === '{' && depth === 0) {
      return index;
    }

    if (char === ';' && depth === 0) {
      return -1;
    }

    index += 1;
  }

  return -1;
}

function collectAbstractMethodOutsideAbstractClassFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.abstractMethodOutsideAbstractClass;
  const findings: ObservedFact[] = [];
  const classPattern =
    /\b(?:(abstract)\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)\b[^{]*\{/gu;

  for (const match of findAllMatches(text, classPattern)) {
    const isAbstract = Boolean(
      /^\s*abstract\s+class\b/u.test(match.matchedText),
    );

    if (isAbstract) {
      continue;
    }

    const openBrace = match.endOffset - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');

    if (closeBrace < 0) {
      continue;
    }

    const body = text.slice(openBrace + 1, closeBrace);
    const abstractMethodPattern =
      /\babstract\s+(?:(?:public|protected|private|static)\s+)*function\s+[A-Za-z_][\w]*\s*\(/gu;

    for (const methodMatch of findAllMatches(body, abstractMethodPattern)) {
      const absoluteStart = openBrace + 1 + methodMatch.startOffset;
      const absoluteEnd = openBrace + 1 + methodMatch.endOffset;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteEnd,
          text: methodMatch.matchedText,
        }),
      );
    }
  }

  return findings;
}

function collectUselessUnsetFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.uselessUnset,
    appliesTo: 'block',
    pattern:
      /\bunset\s*\(\s*(?:\$this->[\w]+|true|false|null|\d+|['"][^'"]*['"])\s*\)/gu,
  });
}

function collectInvalidRegexLiteralFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.invalidRegexLiteral;
  const findings: ObservedFact[] = [];
  const pregPattern =
    /\bpreg_(?:match|match_all|replace|replace_callback|filter|grep|split)\s*\(\s*(['"])([\s\S]*?)\1/gu;

  for (const match of findAllMatches(text, pregPattern)) {
    const literalMatch = /(['"])([\s\S]*?)\1/u.exec(match.matchedText);

    if (!literalMatch) {
      continue;
    }

    const patternLiteral = literalMatch[2];

    if (!isInvalidPhpRegexPattern(patternLiteral)) {
      continue;
    }

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
      }),
    );
  }

  return findings;
}

function isInvalidPhpRegexPattern(literal: string): boolean {
  const delimiter = literal[0];

  if (!delimiter || !/[/#~@%]/u.test(delimiter)) {
    return false;
  }

  let index = 1;
  let escaped = false;

  while (index < literal.length) {
    const char = literal[index];

    if (escaped) {
      escaped = false;
      index += 1;
      continue;
    }

    if (char === '\\') {
      escaped = true;
      index += 1;
      continue;
    }

    if (char === delimiter) {
      const body = literal.slice(1, index);

      try {
        // Validate the extracted PCRE body with a stable delimiter.
        new RegExp(body, 'u');
        return false;
      } catch {
        return true;
      }
    }

    index += 1;
  }

  return true;
}

function collectTodoFixmeMarkerFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.todoFixmeMarker,
    appliesTo: 'block',
    pattern: /(?:\/\/|#|\/\*|\*)\s*.*\b(?:TODO|FIXME|XXX)\b/giu,
  });
}

function collectSelfAssignmentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.selfAssignment,
    appliesTo: 'block',
    pattern:
      /(\$this->[\w]+|\$\w+(?:->[\w]+|\[[^\]]+\])*)\s*=\s*\1\s*;/gu,
  });
}

function collectDefaultParameterNotLastFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.defaultParameterNotLast;
  const findings: ObservedFact[] = [];
  const signaturePattern =
    /\b(?:function\s+[A-Za-z_][\w]*|fn\s*\()\s*\(([^)]*)\)/gu;

  for (const match of findAllMatches(text, signaturePattern)) {
    const paramsMatch = /\(([^)]*)\)/u.exec(match.matchedText);

    if (!paramsMatch) {
      continue;
    }

    const paramsStartInMatch = match.matchedText.indexOf('(') + 1;
    const params = splitParameterList(paramsMatch[1]);
    let sawDefault = false;

    for (const param of params) {
      const trimmed = param.text.trim();

      if (!trimmed) {
        continue;
      }

      const hasDefault = /(?:^|[^=<>!])=(?!=)/u.test(trimmed);

      if (hasDefault) {
        sawDefault = true;
        continue;
      }

      if (sawDefault) {
        const absoluteStart =
          match.startOffset + paramsStartInMatch + param.startOffset;
        const absoluteEnd =
          match.startOffset + paramsStartInMatch + param.endOffset;

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteEnd,
            text: trimmed,
          }),
        );
      }
    }
  }

  return findings;
}

interface ParameterSlice {
  text: string;
  startOffset: number;
  endOffset: number;
}

function splitParameterList(source: string): ParameterSlice[] {
  const params: ParameterSlice[] = [];
  let start = 0;
  let depth = 0;

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];

    if (char === '(' || char === '[') {
      depth += 1;
      continue;
    }

    if (char === ')' || char === ']') {
      depth = Math.max(0, depth - 1);
      continue;
    }

    if (char === ',' && depth === 0) {
      params.push({
        text: source.slice(start, index),
        startOffset: start,
        endOffset: index,
      });
      start = index + 1;
    }
  }

  params.push({
    text: source.slice(start),
    startOffset: start,
    endOffset: source.length,
  });

  return params;
}

function collectEmptyFunctionBodyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.emptyFunctionBody,
    appliesTo: 'block',
    pattern:
      /\bfunction\s+[A-Za-z_][\w]*\s*\([^)]*\)\s*(?::\s*[^{]+)?\{\s*(?:\/\/[^\n]*\s*|\/\*[\s\S]*?\*\/\s*)*\}/gu,
  });
}

function collectUnknownMagicMethodFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.unknownMagicMethod;
  const findings: ObservedFact[] = [];
  const magicPattern = /\bfunction\s+(__[A-Za-z_][\w]*)\s*\(/gu;

  for (const match of findAllMatches(text, magicPattern)) {
    const methodName = /function\s+(__[A-Za-z_][\w]*)\s*\(/u.exec(
      match.matchedText,
    )?.[1];

    if (!methodName || PHP_VALID_MAGIC_METHODS.has(methodName)) {
      continue;
    }

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
      }),
    );
  }

  return findings;
}

function collectCaseInsensitiveDefineFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.caseInsensitiveDefine,
    appliesTo: 'block',
    pattern:
      /\bdefine\s*\(\s*['"][^'"]+['"]\s*,[\s\S]*?,\s*(?:true|1)\s*\)/gu,
  });
}

function collectDeprecatedFilterConstantFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.deprecatedFilterConstant,
    appliesTo: 'block',
    pattern: PHP_DEPRECATED_FILTER_CONSTANTS,
  });
}

function collectEmptyCodeBlockFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.emptyCodeBlock,
    appliesTo: 'block',
    pattern:
      /\b(?:if|else|elseif|try|catch|finally|for|while|foreach)\b[^{;]*\{\s*(?:\/\/[^\n]*\s*|\/\*[\s\S]*?\*\/\s*)*\}/gu,
  });
}

function collectDeprecatedLibxmlEntityLoaderFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.deprecatedLibxmlEntityLoader,
    appliesTo: 'block',
    pattern: /\blibxml_disable_entity_loader\s*\(/gu,
  });
}

function collectRedundantStringCastConcatFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.redundantStringCastConcat,
    appliesTo: 'block',
    pattern: /\(\s*string\s*\)\s*\$\w+\s*\./gu,
  });
}

function collectMissingMemberVisibilityFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.missingMemberVisibility;
  const findings: ObservedFact[] = [];
  const classPattern = /\bclass\s+[A-Za-z_][\w]*\b[^{]*\{/gu;

  for (const match of findAllMatches(text, classPattern)) {
    const openBrace = match.endOffset - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');

    if (closeBrace < 0) {
      continue;
    }

    const body = text.slice(openBrace + 1, closeBrace);
    const memberPattern =
      /^\s*(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/\s*)*(?:function\s+[A-Za-z_]|(?:var\s+)?\$[A-Za-z_])/gmu;

    for (const memberMatch of body.matchAll(memberPattern)) {
      const line = memberMatch[0];
      const trimmed = line.trimStart();

      if (/^(?:public|private|protected)\b/u.test(trimmed)) {
        continue;
      }

      if (/^function\s+__/u.test(trimmed)) {
        continue;
      }

      const matchIndex = memberMatch.index ?? 0;
      const absoluteStart = openBrace + 1 + matchIndex;
      const absoluteEnd = absoluteStart + line.trimEnd().length;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteEnd,
          text: line.trimEnd(),
        }),
      );
    }
  }

  return findings;
}

function collectFunctionComparisonFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.functionComparison,
    appliesTo: 'block',
    pattern:
      /\$\w+\s*(?:==|===|!=|!==)\s*['"][^'"]+['"]|\[\s*\$\w+\s*,\s*['"][^'"]+['"]\s*\]\s*(?:<|>|<=|>=)\s*\[\s*\$\w+\s*,\s*['"][^'"]+['"]\s*\]/gu,
  });
}

function collectUselessPostIncrementFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.uselessPostIncrement,
    appliesTo: 'block',
    pattern:
      /^\s*(?:\$\w+(?:\[[^\]]+\])?(?:->\w+)*|\$this->\w+)\s*\+\+\s*;/gmu,
  });
}

function collectNestedSwitchFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.nestedSwitch;
  const findings: ObservedFact[] = [];
  const switchPattern = /\bswitch\s*\(/gu;

  for (const switchMatch of findAllMatches(text, switchPattern)) {
    const openBrace = findSwitchOpenBrace(text, switchMatch.endOffset);

    if (openBrace < 0) {
      continue;
    }

    const parentDepth = countEnclosingSwitchDepth(text, switchMatch.startOffset);

    if (parentDepth === 0) {
      continue;
    }

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: switchMatch.startOffset,
        endOffset: switchMatch.endOffset,
        text: switchMatch.matchedText,
      }),
    );
  }

  return findings;
}

function countEnclosingSwitchDepth(text: string, offset: number): number {
  let depth = 0;
  let index = 0;

  while (index < offset) {
    index = skipPhpTrivia(text, index);

    if (index >= offset) {
      break;
    }

    const remaining = text.slice(index);

    if (/^\bswitch\b/u.test(remaining)) {
      const openBrace = findNextControlOpenBrace(text, index);

      if (openBrace >= 0 && openBrace < offset) {
        depth += 1;
        index = openBrace + 1;
        continue;
      }
    }

    const char = text[index];

    if (char === '{') {
      index += 1;
      continue;
    }

    if (char === '}') {
      depth = Math.max(0, depth - 1);
      index += 1;
      continue;
    }

    index += 1;
  }

  return depth;
}

function collectInvalidCookieOptionsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.invalidCookieOptions;
  const findings: ObservedFact[] = [];
  const cookiePattern = /\bset(?:raw)?cookie\s*\(/gu;

  for (const match of findAllMatches(text, cookiePattern)) {
    const openParen = match.endOffset - 1;
    const closeParen = findMatchingDelimiter(text, openParen, '(', ')');

    if (closeParen < 0) {
      continue;
    }

    const callText = text.slice(match.startOffset, closeParen + 1);
    const optionsPattern = /['"]([\w-]+)['"]\s*=>/gu;

    for (const optionMatch of findAllMatches(callText, optionsPattern)) {
      const key = /['"]([\w-]+)['"]\s*=>/u.exec(optionMatch.matchedText)?.[1];

      if (!key || PHP_VALID_COOKIE_OPTION_KEYS.has(key.toLowerCase())) {
        continue;
      }

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset + optionMatch.startOffset,
          endOffset: match.startOffset + optionMatch.endOffset,
          text: optionMatch.matchedText,
        }),
      );
    }
  }

  return findings;
}

function collectMissingReturnStatementFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.missingReturnStatement;
  const findings: ObservedFact[] = [];
  const funcPattern =
    /\bfunction\s+(?:&\s*)?[A-Za-z_][\w]*\s*\([^)]*\)\s*:\s*[^{;]+\{/gu;

  for (const match of findAllMatches(text, funcPattern)) {
    const bodyStart = match.endOffset - 1;
    const bodyEnd = findMatchingDelimiter(text, bodyStart, '{', '}');

    if (bodyEnd < 0) {
      continue;
    }

    const body = text.slice(bodyStart + 1, bodyEnd);
    const returnTypeText = /:\s*(\S+)/u.exec(match.matchedText)?.[1] ?? '';

    if (returnTypeText === 'void' || returnTypeText === 'never') {
      continue;
    }

    if (!/\breturn\b/u.test(body)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: bodyEnd + 1,
          text: match.matchedText.trim(),
        }),
      );
    }
  }

  return findings;
}

function collectUninitializedTypedPropertyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.uninitializedTypedProperty;
  const findings: ObservedFact[] = [];
  const classPattern =
    /\b(?:abstract\s+|final\s+)?(?:class|trait)\s+[A-Za-z_][\w]*\b[^{]*\{/gu;

  for (const classMatch of findAllMatches(text, classPattern)) {
    const classOpen = classMatch.endOffset - 1;
    const classClose = findMatchingDelimiter(text, classOpen, '{', '}');

    if (classClose < 0) {
      continue;
    }

    const body = text.slice(classOpen + 1, classClose);
    const typedPropPattern =
      /(?:public|protected|private|var)\s+(?:readonly\s+)?(?:static\s+)?([A-Za-z_\\][\w[\]\\|]*)\s+\$([A-Za-z_][\w]*)\s*(?:(;)|=)/gu;

    for (const propMatch of findAllMatches(body, typedPropPattern)) {
      const matchedText = propMatch.matchedText;

      if (matchedText.trimEnd().endsWith('=')) {
        continue;
      }

      const propName = matchedText.match(
        /\$([A-Za-z_][\w]*)/u,
      )?.[1];

      if (!propName) {
        continue;
      }

      const constructorPattern =
        /\bfunction\s+__construct\s*\(/gu;
      let foundInConstructor = false;

      for (const ctorMatch of findAllMatches(body, constructorPattern)) {
        const ctorDeclEnd = ctorMatch.endOffset;
        let depth = 0;
        let gotParams = false;
        let gotBody = false;
        let ctorBody = '';

        for (let index = ctorDeclEnd; index < body.length; index += 1) {
          const ch = body[index];

          if (!gotParams) {
            if (ch === ')') {
              gotParams = true;
            }
            continue;
          }

          if (!gotBody) {
            if (ch === '{') {
              gotBody = true;
              depth = 1;
            }
            continue;
          }

          if (ch === '{') {
            depth += 1;
            continue;
          }

          if (ch === '}') {
            depth -= 1;

            if (depth === 0) {
              break;
            }
            continue;
          }

          ctorBody += ch;
        }

        if (ctorBody.includes(`$this->${propName}`)) {
          foundInConstructor = true;
          break;
        }
      }

      if (!foundInConstructor) {
        const absoluteStart = classOpen + 1 + propMatch.startOffset;
        const absoluteEnd = classOpen + 1 + propMatch.endOffset;

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteEnd,
            text: matchedText.trim(),
          }),
        );
      }
    }
  }

  return findings;
}

function collectUnusedConstructorParameterFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.unusedConstructorParameter;
  const findings: ObservedFact[] = [];
  const constructorPattern = /\bfunction\s+__construct\s*\(/gu;

  for (const ctorMatch of findAllMatches(text, constructorPattern)) {
    const openParen = ctorMatch.endOffset - 1;
    const paramsClose = findMatchingDelimiter(text, openParen, '(', ')');

    if (paramsClose < 0) {
      continue;
    }

    const paramsText = text.slice(openParen + 1, paramsClose);
    const params = splitParameterList(paramsText);
    const nonPromotedParams: Array<{ name: string; startOffset: number; endOffset: number }> = [];

    for (const param of params) {
      const trimmed = param.text.trim();

      if (!trimmed) {
        continue;
      }

      if (/^(?:public|protected|private|readonly)\b/u.test(trimmed)) {
        continue;
      }

      const nameMatch = /\$([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(trimmed);

      if (!nameMatch) {
        continue;
      }

      nonPromotedParams.push({
        name: nameMatch[1],
        startOffset: openParen + 1 + param.startOffset + (nameMatch.index ?? 0),
        endOffset: openParen + 1 + param.startOffset + (nameMatch.index ?? 0) + nameMatch[0].length,
      });
    }

    if (nonPromotedParams.length === 0) {
      continue;
    }

    const openBrace = findMatchingDelimiter(text, paramsClose, ')', '{');

    if (openBrace < 0) {
      continue;
    }

    const bodyEnd = findMatchingDelimiter(text, openBrace, '{', '}');

    if (bodyEnd < 0) {
      continue;
    }

    const body = text.slice(openBrace + 1, bodyEnd);

    for (const param of nonPromotedParams) {
      const paramRefPattern = new RegExp(
        `\\$${escapeRegExp(param.name)}\\b`,
        'u',
      );

      if (paramRefPattern.test(body)) {
        continue;
      }

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: param.startOffset,
          endOffset: param.endOffset,
          text: `$${param.name}`,
        }),
      );
    }
  }

  return findings;
}

function collectEchoInvalidValueFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.echoInvalidValue;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\becho\s+(?:new\s+\w+\(|array\s*\(|\[)/g,
  });
}

function collectPrintInvalidValueFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.printInvalidValue;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\bprint\s+(?:new\s+\w+\(|array\s*\(|\[)/g,
  });
}

function collectInvalidStringInterpolationTypeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.invalidStringInterpolationType;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\$\{(?:new\s+\w+(?:\s*\([^)]*\))?|array\s*\([^)]*\)|\[[^\]]*\])\s*\}/g,
  });
}

function collectThrowNonExceptionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const KNOWN_EXCEPTION_SUFFIXES = /(?:Exception|Error)$/u;

  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_CORRECTNESS_FACT_KINDS.throwNonException,
    appliesTo: 'block',
    pattern:
      /throw\s+new\s+(?:\\(?:[A-Za-z_][\w]*\\)*)?([A-Za-z_][\w]*)\s*\(/gu,
    predicate: (match) => {
      const className =
        /throw\s+new\s+(?:\\(?:[A-Za-z_][\w]*\\)*)?([A-Za-z_][\w]*)\s*\(/u.exec(
          match.matchedText,
        )?.[1] ?? '';

      return !KNOWN_EXCEPTION_SUFFIXES.test(className);
    },
  });
}

interface StaticPropertySet {
  className: string;
  openBrace: number;
  closeBrace: number;
  staticProperties: Set<string>;
}

function collectPhpClassBodies(text: string): StaticPropertySet[] {
  const results: StaticPropertySet[] = [];
  const classPattern =
    /\b(?:abstract\s+|final\s+)?(?:class|trait)\s+([A-Za-z_][A-Za-z0-9_]*)\b[^{]*\{/gu;

  for (const match of findAllMatches(text, classPattern)) {
    const className = match.matchedText.match(
      /(?:class|trait)\s+([A-Za-z_][A-Za-z0-9_]*)\b/u,
    )?.[1];
    if (!className) continue;

    const openBrace = match.endOffset - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const body = text.slice(openBrace + 1, closeBrace);
    const staticProperties = new Set<string>();
    const staticPropPattern =
      /(?:public|protected|private|static|var)\s+(?:(?:static|public|protected|private)\s+)*(?:readonly\s+)?(?:string|int|float|bool|array|callable|iterable|object|mixed|self|parent|void|never|null|[A-Za-z_][\w]*)?\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*[=;]/gu;

    for (const propMatch of findAllMatches(body, staticPropPattern)) {
      const nameMatch = /\$([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(propMatch.matchedText);
      if (nameMatch) {
        staticProperties.add(nameMatch[1]);
      }
    }

    const staticOnlyPattern =
      /(?<![$\w])static\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*[=;]/gu;
    for (const propMatch of findAllMatches(body, staticOnlyPattern)) {
      const nameMatch = /\$([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(propMatch.matchedText);
      if (nameMatch) {
        staticProperties.add(nameMatch[1]);
      }
    }

    results.push({
      className,
      openBrace,
      closeBrace,
      staticProperties,
    });
  }

  return results;
}

function collectUndefinedStaticPropertyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.undefinedStaticProperty;
  const findings: ObservedFact[] = [];
  const classBodies = collectPhpClassBodies(text);
  const classMap = new Map<string, StaticPropertySet>();
  for (const cb of classBodies) {
    classMap.set(cb.className, cb);
  }

  const accessPattern =
    /(?:(?:([A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][\w]*)*)|self|static|parent)\s*::\s*\$([A-Za-z_][A-Za-z0-9_]*))\b/gu;

  for (const match of findAllMatches(text, accessPattern)) {
    const fullMatch = match.matchedText;
    const accessMatch =
      /(?:(?:([A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][\w]*)*)|self|static|parent))\s*::\s*\$([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(
        fullMatch,
      );
    if (!accessMatch) continue;

    const rawClassRef = accessMatch[1];
    const propName = accessMatch[2];
    const keyword = /^(self|static|parent)$/u.exec(
      fullMatch.split('::')[0].trim(),
    )?.[1];

    if (keyword === 'parent') continue;

    let resolvedClass: string | undefined;
    if (keyword === 'self' || keyword === 'static') {
      const pos = match.startOffset;
      for (const cb of classBodies) {
        if (pos > cb.openBrace && pos < cb.closeBrace) {
          resolvedClass = cb.className;
          break;
        }
      }
      if (!resolvedClass) continue;
    } else if (rawClassRef) {
      const shortName = rawClassRef.split('\\').pop() ?? rawClassRef;
      resolvedClass = shortName;
    } else {
      continue;
    }

    const classInfo = classMap.get(resolvedClass);
    if (!classInfo) continue;

    if (classInfo.staticProperties.has(propName)) continue;

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: `$${propName}`,
      }),
    );
  }

  return findings;
}
