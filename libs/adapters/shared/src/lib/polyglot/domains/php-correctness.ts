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
  undefinedFunction:
    'php.correctness.undefined-function',
  undefinedMethod:
    'php.correctness.undefined-method',
  invalidStaticMethod:
    'php.correctness.invalid-static-method',
  invalidAttributeClass:
    'php.correctness.invalid-attribute-class',
  invalidUseKeyword:
    'php.correctness.invalid-use-keyword',
  inconsistentPrintfParams:
    'php.correctness.inconsistent-printf-params',
  undefinedProperty:
    'php.correctness.undefined-property',
  undefinedVariable:
    'php.correctness.undefined-variable',
  inaccessibleProperty:
    'php.correctness.inaccessible-property',
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
    ...collectUndefinedFunctionFacts(text, detector),
    ...collectUndefinedMethodFacts(text, detector),
    ...collectInvalidStaticMethodFacts(text, detector),
    ...collectInvalidAttributeClassFacts(text, detector),
    ...collectInvalidUseKeywordFacts(text, detector),
    ...collectInconsistentPrintfParamsFacts(text, detector),
    ...collectUndefinedPropertyFacts(text, detector),
    ...collectUndefinedVariableFacts(text, detector),
    ...collectInaccessiblePropertyFacts(text, detector),
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

interface ClassBodyInfo {
  className: string;
  openBrace: number;
  closeBrace: number;
  staticProperties: Set<string>;
  methods: Map<string, boolean>;
  hasExtends: boolean;
  isTrait: boolean;
}

function collectPhpClassBodies(text: string): ClassBodyInfo[] {
  const results: ClassBodyInfo[] = [];
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

    const hasExtends = /\bextends\b/u.test(match.matchedText);
    const isTrait = /\btrait\s+/u.test(match.matchedText);
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

    const methods = new Map<string, boolean>();
    const methodPattern =
      /(?:public|protected|private)?\s*(?:static\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu;
    for (const methodMatch of findAllMatches(body, methodPattern)) {
      const methodSrc = methodMatch.matchedText;
      const nameMatch = /function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/u.exec(methodSrc);
      if (!nameMatch) continue;
      const isStatic = /static\s+function/u.test(methodSrc);
      methods.set(nameMatch[1], isStatic);
    }

    results.push({
      className,
      openBrace,
      closeBrace,
      staticProperties,
      methods,
      hasExtends,
      isTrait,
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
  const classMap = new Map<string, ClassBodyInfo>();
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

const PHP_BUILTIN_FUNCTIONS = new Set<string>([
  'echo', 'print', 'isset', 'empty', 'unset', 'die', 'exit',
  'count', 'define', 'defined', 'class_exists', 'function_exists',
  'method_exists', 'property_exists', 'interface_exists', 'trait_exists',
  'enum_exists', 'get_class', 'get_parent_class', 'get_called_class',
  'gettype', 'settype', 'intval', 'floatval', 'strval', 'boolval',
  'is_null', 'is_array', 'is_bool', 'is_callable', 'is_countable',
  'is_double', 'is_float', 'is_int', 'is_integer', 'is_iterable',
  'is_long', 'is_numeric', 'is_object', 'is_real', 'is_resource',
  'is_scalar', 'is_string', 'compact', 'extract', 'list', 'array',
  'explode', 'implode', 'join', 'substr', 'strlen', 'strpos', 'strrpos',
  'stripos', 'strripos', 'str_replace', 'str_ireplace', 'trim', 'ltrim',
  'rtrim', 'sprintf', 'printf', 'vprintf', 'vsprintf',
  'sscanf',
  'fopen', 'fclose', 'fread', 'fwrite', 'fgets', 'file_get_contents',
  'file_put_contents', 'file_exists', 'is_file', 'is_dir', 'mkdir',
  'rmdir', 'unlink', 'copy', 'rename', 'chmod', 'chown', 'touch',
  'time', 'strtotime', 'mktime', 'gmmktime', 'checkdate',
  'array_merge', 'array_slice', 'array_splice', 'array_keys',
  'array_values', 'array_pop', 'array_push', 'array_shift',
  'array_unshift', 'array_reverse', 'array_unique', 'array_search',
  'in_array', 'array_key_exists', 'array_map', 'array_filter',
  'array_reduce', 'array_walk', 'sort', 'rsort', 'asort', 'arsort',
  'ksort', 'krsort', 'usort', 'uasort', 'uksort',
  'preg_match', 'preg_match_all', 'preg_replace', 'preg_split',
  'preg_grep', 'preg_quote',
  'serialize', 'unserialize', 'json_encode', 'json_decode',
  'json_last_error', 'json_last_error_msg',
  'header', 'headers_sent', 'session_start', 'session_destroy',
  'session_id', 'session_name', 'session_set_cookie_params',
  'setcookie', 'setrawcookie',
  'error_reporting', 'trigger_error', 'set_error_handler',
  'set_exception_handler', 'register_shutdown_function',
  'ob_start', 'ob_end_clean', 'ob_end_flush', 'ob_get_contents',
  'ob_clean', 'ob_flush',
  'curl_init', 'curl_setopt', 'curl_exec', 'curl_close',
  'curl_error', 'curl_getinfo', 'curl_multi_init',
  'stream_context_create', 'stream_get_contents',
  'socket_create', 'socket_connect', 'socket_write', 'socket_read',
  'socket_close',
  'mysqli_connect', 'mysqli_query', 'mysqli_fetch_assoc',
  'mysqli_fetch_array', 'mysqli_fetch_row', 'mysqli_num_rows',
  'mysqli_affected_rows', 'mysqli_insert_id', 'mysqli_error',
  'mysqli_close', 'mysqli_prepare', 'mysqli_stmt_execute',
  'mysqli_stmt_bind_param', 'mysqli_stmt_get_result',
  'hash', 'hash_hmac', 'hash_algos', 'md5', 'sha1', 'crc32',
  'password_hash', 'password_verify', 'password_needs_rehash',
  'openssl_encrypt', 'openssl_decrypt', 'openssl_random_pseudo_bytes',
  'openssl_cipher_iv_length', 'openssl_get_cipher_methods',
  'random_bytes', 'random_int',
  'openssl_csr_new', 'openssl_sign', 'openssl_verify',
  'sodium_crypto_aead_encrypt', 'sodium_crypto_aead_decrypt',
  'sodium_crypto_secretbox', 'sodium_crypto_secretbox_open',
  'sodium_crypto_box', 'sodium_crypto_box_open',
  'sodium_crypto_sign', 'sodium_crypto_sign_verify',
  'xml_parse', 'xml_parser_create', 'xml_set_element_handler',
  'xml_set_character_data_handler', 'xml_get_error_code',
  'xml_error_string',
  'dom_import_simplexml',
  'simplexml_load_string', 'simplexml_load_file',
  'simplexml_import_dom',
  'filter_var', 'filter_input', 'filter_var_array', 'filter_input_array',
  'filter_has_var', 'filter_id', 'filter_list',
  'ctype_alnum', 'ctype_alpha', 'ctype_cntrl', 'ctype_digit',
  'ctype_graph', 'ctype_lower', 'ctype_print', 'ctype_punct',
  'ctype_space', 'ctype_upper', 'ctype_xdigit',
  'posix_getpid', 'posix_getpwuid', 'posix_kill',
  'exec', 'shell_exec', 'system', 'passthru', 'escapeshellcmd',
  'escapeshellarg', 'proc_open', 'proc_close', 'proc_get_status',
  'date', 'date_default_timezone_set', 'date_create', 'date_format',
  'date_interval_create_from_date_string', 'date_diff',
  'str_contains', 'str_starts_with', 'str_ends_with',
  'strtolower', 'strtoupper', 'ucfirst', 'lcfirst', 'ucwords',
  'str_pad', 'str_repeat', 'str_shuffle', 'str_split', 'str_word_count',
  'strcspn', 'strpbrk', 'strrev', 'strspn', 'strstr',
  'chunk_split', 'html_entity_decode', 'htmlentities',
  'htmlspecialchars', 'htmlspecialchars_decode',
  'levenshtein', 'nl2br', 'number_format', 'ord',
  'parse_str', 'quoted_printable_decode', 'quotemeta',
  'soundex', 'str_getcsv', 'str_rot13',
  'strcasecmp', 'strcmp', 'strcoll',
  'strip_tags', 'stripcslashes', 'stripslashes',
  'stristr', 'strnatcasecmp', 'strnatcmp',
  'strncasecmp', 'strncmp', 'strtok',
  'strtr', 'substr_compare', 'substr_count', 'substr_replace',
  'wordwrap',
  'debug_backtrace', 'debug_print_backtrace', 'error_get_last',
  'error_log',
  'file', 'fileatime', 'filectime', 'filegroup', 'fileinode',
  'filemtime', 'fileowner', 'fileperms', 'filesize', 'filetype',
  'flock', 'fnmatch', 'fpassthru', 'fputcsv', 'fputs',
  'fscanf', 'fseek', 'fstat', 'ftell', 'ftruncate',
  'glob', 'is_executable', 'is_link', 'is_readable',
  'is_uploaded_file', 'is_writable', 'is_writeable',
  'link', 'linkinfo', 'lstat', 'move_uploaded_file',
  'parse_ini_file', 'parse_ini_string', 'pathinfo', 'basename', 'dirname',
  'pclose', 'popen', 'readfile', 'readlink',
  'realpath', 'realpath_cache_get', 'realpath_cache_size',
  'rewind', 'set_file_buffer', 'stat',
  'symlink', 'tempnam', 'tmpfile',
  'finfo_open', 'finfo_file', 'finfo_close', 'mime_content_type',
  'abs', 'acos', 'acosh', 'asin', 'asinh', 'atan', 'atan2',
  'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh',
  'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1',
  'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'intdiv',
  'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log',
  'log10', 'log1p', 'max', 'min', 'mt_getrandmax', 'mt_rand',
  'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand',
  'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh',
  'class_alias', 'constant', 'die', 'eval', 'exit',
  'get_class_methods', 'get_class_vars',
  'get_declared_classes', 'get_declared_interfaces',
  'get_declared_traits', 'get_mangled_object_vars',
  'get_object_vars', 'interface_exists', 'is_a', 'is_subclass_of',
  'call_user_func', 'call_user_func_array', 'forward_static_call',
  'forward_static_call_array', 'func_get_arg', 'func_get_args',
  'func_num_args', 'register_tick_function', 'unregister_tick_function',
  'iterator_count', 'iterator_to_array',
  'spl_autoload_call', 'spl_autoload_extensions',
  'spl_autoload_functions', 'spl_autoload_register',
  'spl_autoload_unregister', 'spl_classes',
  'spl_object_hash', 'spl_object_id',
  'class_implements', 'class_parents', 'class_uses',
  'iterator_apply',
  'assert',
]);

const PHP_KEYWORD_EXCLUSIONS = new Set([
  'if', 'elseif', 'while', 'for', 'foreach', 'switch', 'catch',
  'isset', 'empty', 'unset', 'die', 'exit', 'echo', 'print',
  'list', 'eval', 'fn', 'yield', 'declare',
  'self', 'parent', 'static',
]);

function collectUndefinedFunctionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.undefinedFunction;
  const findings: ObservedFact[] = [];

  const callPattern = /(?<![$\w>):\\])([A-Za-z_][A-Za-z0-9_]*)\(/gu;

  const definitions = new Set<string>();
  const defPattern = /\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu;
  for (const defMatch of findAllMatches(text, defPattern)) {
    const name = /\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/u.exec(defMatch.matchedText)?.[1];
    if (name) definitions.add(name);
  }

  for (const call of findAllMatches(text, callPattern)) {
    const name = /([A-Za-z_][A-Za-z0-9_]*)\s*\(/u.exec(call.matchedText)?.[1];
    if (!name) continue;

    const preceding = text.slice(Math.max(0, call.startOffset - 100), call.startOffset);
    if (
      /\b(?:function|class|interface|trait|enum|new|instanceof)\s+$/u.test(preceding) ||
      /\b(?:public|private|protected|static|readonly|abstract|final)\s+$/u.test(preceding) ||
      /\breturn\s+new\s+$/u.test(preceding) ||
      /\bthrow\s+new\s+\\$/u.test(preceding) ||
      /#\[\s*$/u.test(preceding)
    ) {
      continue;
    }

    if (definitions.has(name)) continue;
    if (PHP_BUILTIN_FUNCTIONS.has(name)) continue;
    if (PHP_KEYWORD_EXCLUSIONS.has(name)) continue;

    const callStart = call.startOffset + call.matchedText.indexOf(name);
    const callEnd = callStart + name.length;

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: callStart,
        endOffset: callEnd,
        text: name,
      }),
    );
  }

  return findings;
}

const PHP_TRAIT_COMMON_METHODS = new Set([
  'boot', 'initialize', 'setup', 'teardown',
]);

function collectUndefinedMethodFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.undefinedMethod;
  const findings: ObservedFact[] = [];
  const classBodies = collectPhpClassBodies(text);

  const thisCallPattern = /\$this\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu;
  for (const match of findAllMatches(text, thisCallPattern)) {
    const nameMatch = /\$this\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/u.exec(match.matchedText);
    if (!nameMatch) continue;
    const methodName = nameMatch[1];

    if (PHP_VALID_MAGIC_METHODS.has(methodName)) continue;
    if (PHP_TRAIT_COMMON_METHODS.has(methodName)) continue;

    const pos = match.startOffset;
    let foundClass = false;
    let methodExists = false;
    let extendsClass = false;

    for (const cb of classBodies) {
      if (pos > cb.openBrace && pos < cb.closeBrace) {
        foundClass = true;
        extendsClass = cb.hasExtends;
        methodExists = cb.methods.has(methodName);
        break;
      }
    }

    if (!foundClass) continue;
    if (extendsClass) continue;
    if (methodExists) continue;

    const callStart = match.startOffset + match.matchedText.indexOf(methodName);
    const callEnd = callStart + methodName.length;

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: callStart,
        endOffset: callEnd,
        text: methodName,
      }),
    );
  }

  const selfCallPattern = /(?<!\$)(?:self|static)\s*::\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu;
  for (const match of findAllMatches(text, selfCallPattern)) {
    const nameMatch = /(?:self|static)\s*::\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/u.exec(match.matchedText);
    if (!nameMatch) continue;
    const methodName = nameMatch[1];

    if (PHP_VALID_MAGIC_METHODS.has(methodName)) continue;
    if (PHP_TRAIT_COMMON_METHODS.has(methodName)) continue;

    const pos = match.startOffset;
    let foundClass = false;
    let methodExists = false;
    let extendsClass = false;

    for (const cb of classBodies) {
      if (pos > cb.openBrace && pos < cb.closeBrace) {
        foundClass = true;
        extendsClass = cb.hasExtends;
        methodExists = cb.methods.has(methodName);
        break;
      }
    }

    if (!foundClass) continue;
    if (extendsClass) continue;
    if (methodExists) continue;

    const callStart = match.startOffset + match.matchedText.indexOf(methodName);
    const callEnd = callStart + methodName.length;

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: callStart,
        endOffset: callEnd,
        text: methodName,
      }),
    );
  }

  return findings;
}

function collectInvalidStaticMethodFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.invalidStaticMethod;
  const findings: ObservedFact[] = [];
  const classBodies = collectPhpClassBodies(text);

  const staticCallPattern = /(?<!\$)(?:self|static)\s*::\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu;
  for (const match of findAllMatches(text, staticCallPattern)) {
    const nameMatch = /(?:self|static)\s*::\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/u.exec(match.matchedText);
    if (!nameMatch) continue;
    const methodName = nameMatch[1];

    if (PHP_VALID_MAGIC_METHODS.has(methodName)) continue;
    if (PHP_TRAIT_COMMON_METHODS.has(methodName)) continue;

    const pos = match.startOffset;
    let foundClass = false;
    let methodIsStatic: boolean | undefined;
    let extendsClass = false;

    for (const cb of classBodies) {
      if (pos > cb.openBrace && pos < cb.closeBrace) {
        foundClass = true;
        extendsClass = cb.hasExtends;
        methodIsStatic = cb.methods.get(methodName);
        break;
      }
    }

    if (!foundClass) continue;
    if (extendsClass) continue;
    if (methodIsStatic === undefined) continue;
    if (methodIsStatic) continue;

    const callStart = match.startOffset + match.matchedText.indexOf(methodName);
    const callEnd = callStart + methodName.length;

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: callStart,
        endOffset: callEnd,
        text: methodName,
      }),
    );
  }

  return findings;
}

function collectInvalidAttributeClassFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.invalidAttributeClass;
  const findings: ObservedFact[] = [];
  const classPattern = /\b(?:abstract\s+)?(?:class|interface)\s+([A-Za-z_][A-Za-z0-9_]*)\b[^{]*\{/gu;

  for (const match of findAllMatches(text, classPattern)) {
    const openBrace = match.endOffset - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const beforeMatch = text.slice(Math.max(0, match.startOffset - 200), match.startOffset);
    const hasAttribute = /#\[\s*(?:\\?[A-Za-z_][\w]*\\)*Attribute\b/u.test(beforeMatch);

    if (!hasAttribute) continue;

    const preamble = match.matchedText;
    const isInterface = /\binterface\s+/u.test(preamble);
    const isAbstractClass = /\babstract\s+class\b/u.test(preamble);

    if (isAbstractClass) {
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

    if (isInterface) {
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

    const body = text.slice(openBrace + 1, closeBrace);
    const constructorPattern = /(?:private|protected)\s+function\s+__construct\s*\(/gu;
    const ctorMatch = findAllMatches(body, constructorPattern);
    if (ctorMatch.length > 0) {
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

function collectInvalidUseKeywordFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.invalidUseKeyword;
  const findings: ObservedFact[] = [];

  const namedPattern = /\b(?:abstract\s+|final\s+)?(?:class|interface|trait)\s+([A-Za-z_][A-Za-z0-9_]*)\b[^{]*\{/gu;
  const anonymousPattern = /(?:new\s+)?class\b[^{]*\{/gu;

  const classMatches: Array<{ preamble: string; openBrace: number; closeBrace: number; isInterface: boolean; isAnonymous: boolean }> = [];

  for (const match of findAllMatches(text, namedPattern)) {
    const openBrace = match.endOffset - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;
    classMatches.push({
      preamble: match.matchedText,
      openBrace,
      closeBrace,
      isInterface: /\binterface\s+/u.test(match.matchedText),
      isAnonymous: false,
    });
  }

  for (const match of findAllMatches(text, anonymousPattern)) {
    if (/\b(?:class|interface|trait)\s+[A-Za-z_][A-Za-z0-9_]*\b/u.test(match.matchedText)) continue;
    const openBrace = match.endOffset - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;
    classMatches.push({
      preamble: match.matchedText,
      openBrace,
      closeBrace,
      isInterface: false,
      isAnonymous: true,
    });
  }

  for (const { preamble, openBrace, closeBrace, isInterface, isAnonymous } of classMatches) {

    const body = text.slice(openBrace + 1, closeBrace);
    const usePattern = /\buse\s+([A-Za-z_][A-Za-z0-9_]*)\s*;/gu;

    for (const useMatch of findAllMatches(body, usePattern)) {
      const traitName = /use\s+([A-Za-z_][A-Za-z0-9_]*)\s*;/u.exec(useMatch.matchedText)?.[1];
      if (!traitName) continue;

      if (isInterface) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: openBrace + 1 + useMatch.startOffset,
            endOffset: openBrace + 1 + useMatch.endOffset,
            text: useMatch.matchedText,
          }),
        );
        continue;
      }

      if (isAnonymous) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: openBrace + 1 + useMatch.startOffset,
            endOffset: openBrace + 1 + useMatch.endOffset,
            text: useMatch.matchedText,
          }),
        );
        continue;
      }

      const allClasses = collectPhpClassBodies(text);
      for (const cb of allClasses) {
        if (cb.className === traitName && !cb.isTrait) {
          findings.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: openBrace + 1 + useMatch.startOffset,
              endOffset: openBrace + 1 + useMatch.endOffset,
              text: useMatch.matchedText,
            }),
          );
          break;
        }
      }
    }
  }

  return findings;
}

interface PrintfCallInfo {
  startOffset: number;
  endOffset: number;
  formatString: string;
  argCount: number;
}

function collectPhpPrintfCalls(text: string): PrintfCallInfo[] {
  const calls: PrintfCallInfo[] = [];
  const printfPattern = /\b(?:sprintf|sscanf|fscanf)\s*\(/gu;

  for (const match of findAllMatches(text, printfPattern)) {
    const openParen = match.endOffset - 1;
    const closeParen = findMatchingDelimiter(text, openParen, '(', ')');
    if (closeParen < 0) continue;

    const callText = text.slice(match.startOffset, closeParen + 1);
    const isSscanfOrFscanf = /\b(?:sscanf|fscanf)\s*\(/u.test(callText);

    const argsText = text.slice(openParen + 1, closeParen);
    const args = splitTopLevelCommaArgs(argsText);

    const formatIndex = isSscanfOrFscanf ? 1 : 0;
    if (args.length <= formatIndex) continue;

    const formatArg = args[formatIndex].text.trim();
    const formatMatch = /^(['"])([\s\S]*?)\1$/u.exec(formatArg);
    if (!formatMatch) continue;

    const formatString = formatMatch[2];
    const argCount = isSscanfOrFscanf
      ? args.length - 2
      : args.length - 1;

    calls.push({
      startOffset: match.startOffset,
      endOffset: closeParen + 1,
      formatString,
      argCount,
    });
  }

  return calls;
}

interface TopLevelArg {
  text: string;
}

function splitTopLevelCommaArgs(source: string): TopLevelArg[] {
  const args: TopLevelArg[] = [];
  let start = 0;
  let depthParen = 0;
  let depthBracket = 0;
  let depthBrace = 0;

  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (char === '(') { depthParen += 1; continue; }
    if (char === ')') { depthParen = Math.max(0, depthParen - 1); continue; }
    if (char === '[') { depthBracket += 1; continue; }
    if (char === ']') { depthBracket = Math.max(0, depthBracket - 1); continue; }
    if (char === '{') { depthBrace += 1; continue; }
    if (char === '}') { depthBrace = Math.max(0, depthBrace - 1); continue; }
    if (char === ',' && depthParen === 0 && depthBracket === 0 && depthBrace === 0) {
      args.push({ text: source.slice(start, index).trim() });
      start = index + 1;
    }
  }

  const last = source.slice(start).trim();
  if (last.length > 0) {
    args.push({ text: last });
  }

  return args;
}

function countPrintfPlaceholders(format: string): number {
  const placeholderPattern = /%(?:\d+\$)?[+\- 0']?\d*(?:\.\d+)?[sdfcboxXeEuUgGhH%]/gu;
  const positionalArgs = new Set<string>();
  let count = 0;
  let hasPositional = false;

  for (const pm of format.matchAll(placeholderPattern)) {
    const spec = pm[0];
    if (spec.endsWith('%')) continue;

    const posMatch = /%(\d+)\$/u.exec(spec);
    if (posMatch) {
      hasPositional = true;
      positionalArgs.add(posMatch[1]);
    } else {
      count += 1;
    }
  }

  if (hasPositional) {
    return positionalArgs.size;
  }

  return count;
}

function collectInconsistentPrintfParamsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.inconsistentPrintfParams;
  const findings: ObservedFact[] = [];
  const calls = collectPhpPrintfCalls(text);

  for (const call of calls) {
    const placeholderCount = countPrintfPlaceholders(call.formatString);
    const isSscanf = /\bsscanf\b/u.test(text.slice(call.startOffset, call.startOffset + 30));
    const isFscanf = /\bfscanf\b/u.test(text.slice(call.startOffset, call.startOffset + 30));

    let expectedArgs: number;
    if (isSscanf || isFscanf) {
      expectedArgs = 1 + placeholderCount;
    } else {
      expectedArgs = placeholderCount;
    }

    if (call.argCount !== expectedArgs) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: call.startOffset,
          endOffset: call.endOffset,
          text: text.slice(call.startOffset, call.endOffset),
        }),
      );
    }
  }

  return findings;
}

interface ClassPropertyInfo {
  className: string;
  openBrace: number;
  closeBrace: number;
  properties: Set<string>;
  hasExtends: boolean;
  hasMagicGetSet: boolean;
  propertyVisibility: Map<string, 'public' | 'protected' | 'private'>;
  parentClassName: string | undefined;
  parentPrivateProps: Set<string>;
  parentProtectedProps: Set<string>;
}

function collectPhpClassPropertyInfo(text: string): ClassPropertyInfo[] {
  const results: ClassPropertyInfo[] = [];
  const classPattern = /\b(?:abstract\s+|final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)\b[^{]*\{/gu;

  for (const match of findAllMatches(text, classPattern)) {
    const className = match.matchedText.match(/(?:class)\s+([A-Za-z_][A-Za-z0-9_]*)\b/u)?.[1];
    if (!className) continue;

    const openBrace = match.endOffset - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const hasExtends = /\bextends\b/u.test(match.matchedText);
    const parentClassName = hasExtends
      ? /extends\s+([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(match.matchedText)?.[1]
      : undefined;
    const body = text.slice(openBrace + 1, closeBrace);

    const properties = new Set<string>();
    const propertyVisibility = new Map<string, 'public' | 'protected' | 'private'>();

    const propPattern = /(public|protected|private|var)\s+(?:readonly\s+)?(?:static\s+)?(?:[A-Za-z_\\][\w[\]\\|]*\s+)?\$([A-Za-z_][A-Za-z0-9_]*)\s*[=;]/gu;
    for (const propMatch of findAllMatches(body, propPattern)) {
      const nameMatch = /\$([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(propMatch.matchedText);
      if (!nameMatch) continue;
      const propName = nameMatch[1];
      properties.add(propName);
      const visMatch = /(public|protected|private|var)/u.exec(propMatch.matchedText);
      if (visMatch) {
        propertyVisibility.set(propName, visMatch[1] === 'var' ? 'public' : visMatch[1] as 'public' | 'protected' | 'private');
      }
    }

    const simplePropPattern = /(?:public|protected|private|var)\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*[=;]/gu;
    for (const propMatch of findAllMatches(body, simplePropPattern)) {
      const nameMatch = /\$([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(propMatch.matchedText);
      if (!nameMatch) continue;
      const propName = nameMatch[1];
      properties.add(propName);
      if (!propertyVisibility.has(propName)) {
        const visMatch = /(public|protected|private|var)/u.exec(propMatch.matchedText);
        if (visMatch) {
          propertyVisibility.set(propName, visMatch[1] === 'var' ? 'public' : visMatch[1] as 'public' | 'protected' | 'private');
        }
      }
    }

    const constructorPromotedPattern = /\bfunction\s+__construct\s*\(([^)]*)\)/gu;
    for (const ctorMatch of findAllMatches(body, constructorPromotedPattern)) {
      const paramsText = /__construct\s*\(([^)]*)\)/u.exec(ctorMatch.matchedText)?.[1] ?? '';
      const promotedPattern = /(public|protected|private)\s+(?:readonly\s+)?(?:[A-Za-z_\\][\w[\]\\|]*\s+)?\$([A-Za-z_][A-Za-z0-9_]*)\b/gu;
      for (const promMatch of findAllMatches(paramsText, promotedPattern)) {
        const nameMatch = /\$([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(promMatch.matchedText);
        if (!nameMatch) continue;
        const propName = nameMatch[1];
        properties.add(propName);
        if (!propertyVisibility.has(propName)) {
          const visMatch = /(public|protected|private)/u.exec(promMatch.matchedText);
          if (visMatch) {
            propertyVisibility.set(propName, visMatch[1] as 'public' | 'protected' | 'private');
          }
        }
      }
    }

    const hasMagicGetSet = /\bfunction\s+(?:__get|__set)\s*\(/u.test(body);

    results.push({
      className,
      openBrace,
      closeBrace,
      properties,
      hasExtends,
      hasMagicGetSet,
      propertyVisibility,
      parentClassName,
      parentPrivateProps: new Set(),
      parentProtectedProps: new Set(),
    });
  }

  const classByName = new Map<string, ClassPropertyInfo>();
  for (const ci of results) {
    classByName.set(ci.className, ci);
  }

  for (const ci of results) {
    if (ci.parentClassName) {
      const parent = classByName.get(ci.parentClassName);
      if (parent) {
        for (const [propName, vis] of parent.propertyVisibility) {
          if (vis === 'private') {
            ci.parentPrivateProps.add(propName);
          } else if (vis === 'protected') {
            ci.parentProtectedProps.add(propName);
          }
        }
      }
    }
  }

  return results;
}

function collectUndefinedPropertyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.undefinedProperty;
  const findings: ObservedFact[] = [];
  const classInfoList = collectPhpClassPropertyInfo(text);

  const thisAccessPattern = /\$this\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()/gu;

  for (const match of findAllMatches(text, thisAccessPattern)) {
    const propName = /\$this\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(match.matchedText)?.[1];
    if (!propName) continue;

    const pos = match.startOffset;
    let foundClass: ClassPropertyInfo | undefined;

    for (const ci of classInfoList) {
      if (pos > ci.openBrace && pos < ci.closeBrace) {
        foundClass = ci;
        break;
      }
    }

    if (!foundClass) continue;
    if (foundClass.hasExtends) continue;
    if (foundClass.hasMagicGetSet) continue;
    if (foundClass.properties.has(propName)) continue;

    const accessStart = match.startOffset + match.matchedText.indexOf(`->${propName}`);
    const accessEnd = accessStart + propName.length + 2;

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: accessStart,
        endOffset: accessEnd,
        text: `->${propName}`,
      }),
    );
  }

  return findings;
}

interface FunctionBodyRange {
  bodyStart: number;
  bodyEnd: number;
  isStatic: boolean;
  params: Set<string>;
}

function collectFunctionBodyRanges(
  text: string,
  classBodies: ClassBodyInfo[],
): FunctionBodyRange[] {
  const ranges: FunctionBodyRange[] = [];
  const functionPattern =
    /(?:(?:public|protected|private)\s+)?(?:(?:static)\s+)?function\s+(?:&\s*)?[A-Za-z_][A-Za-z0-9_]*\s*\(/gu;

  for (const match of findAllMatches(text, functionPattern)) {
    const openParen = match.endOffset - 1;
    const closeParen = findMatchingDelimiter(text, openParen, '(', ')');
    if (closeParen < 0) continue;

    const paramsText = text.slice(openParen + 1, closeParen);
    const params = new Set<string>();
    const paramPattern = /\$([A-Za-z_][A-Za-z0-9_]*)\b/gu;
    for (const pm of findAllMatches(paramsText, paramPattern)) {
      const name = /\$([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(pm.matchedText)?.[1];
      if (name) params.add(name);
    }

    const nextNonSpace = text.slice(closeParen + 1).search(/\S/u);
    const afterParenOffset = closeParen + 1 + (nextNonSpace >= 0 ? nextNonSpace : 0);

    if (text[afterParenOffset] === ':') {
      const returnTypeEnd = text.indexOf('{', afterParenOffset);
      if (returnTypeEnd < 0) continue;
      const bodyStart = returnTypeEnd;
      const bodyEnd = findMatchingDelimiter(text, bodyStart, '{', '}');
      if (bodyEnd < 0) continue;

      const isStatic = /\bstatic\s+function\b/u.test(match.matchedText);

      ranges.push({ bodyStart, bodyEnd, isStatic, params });
    } else if (text[afterParenOffset] === '{') {
      const bodyStart = afterParenOffset;
      const bodyEnd = findMatchingDelimiter(text, bodyStart, '{', '}');
      if (bodyEnd < 0) continue;

      const isStatic = /\bstatic\s+function\b/u.test(match.matchedText);

      ranges.push({ bodyStart, bodyEnd, isStatic, params });
    }
  }

  const arrowPattern = /fn\s*\(/gu;
  for (const match of findAllMatches(text, arrowPattern)) {
    const openParen = match.endOffset - 1;
    const closeParen = findMatchingDelimiter(text, openParen, '(', ')');
    if (closeParen < 0) continue;

    const paramsText = text.slice(openParen + 1, closeParen);
    const params = new Set<string>();
    const paramPattern = /\$([A-Za-z_][A-Za-z0-9_]*)\b/gu;
    for (const pm of findAllMatches(paramsText, paramPattern)) {
      const name = /\$([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(pm.matchedText)?.[1];
      if (name) params.add(name);
    }

    const arrowStart = text.indexOf('=>', closeParen);
    if (arrowStart < 0) continue;

    const isStatic = /\bstatic\s+fn\b/u.test(text.slice(Math.max(0, match.startOffset - 10), match.endOffset));

    const exprStart = arrowStart + 2;
    const exprEnd = text.indexOf(';', exprStart);
    if (exprEnd < 0) continue;

    ranges.push({ bodyStart: exprStart, bodyEnd: exprEnd, isStatic, params });
  }

  for (const cb of classBodies) {
    const body = text.slice(cb.openBrace + 1, cb.closeBrace);
    const closurePattern = /\bfunction\s*\(/gu;
    for (const cm of findAllMatches(body, closurePattern)) {
      const absStart = cb.openBrace + 1 + cm.startOffset;
      const openParen = absStart + (cm.endOffset - cm.startOffset) - 1;
      const closeParen = findMatchingDelimiter(text, openParen, '(', ')');
      if (closeParen < 0) continue;

      const paramsText = text.slice(openParen + 1, closeParen);
      const params = new Set<string>();
      const paramPattern = /\$([A-Za-z_][A-Za-z0-9_]*)\b/gu;
      for (const pm of findAllMatches(paramsText, paramPattern)) {
        const name = /\$([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(pm.matchedText)?.[1];
        if (name) params.add(name);
      }

      const nextNonSpace = text.slice(closeParen + 1).search(/\S/u);
      const afterParenOffset2 = closeParen + 1 + (nextNonSpace >= 0 ? nextNonSpace : 0);
      if (text[afterParenOffset2] !== '{') continue;

      const bodyStart = afterParenOffset2;
      const bodyEnd = findMatchingDelimiter(text, bodyStart, '{', '}');
      if (bodyEnd < 0) continue;

      ranges.push({ bodyStart, bodyEnd, isStatic: false, params });
    }
  }

  return ranges;
}

function collectUndefinedVariableFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.undefinedVariable;
  const findings: ObservedFact[] = [];
  const classBodies = collectPhpClassBodies(text);
  const fnBodies = collectFunctionBodyRanges(text, classBodies);

  for (const fn of fnBodies) {
    if (fn.bodyStart >= fn.bodyEnd) continue;

    const bodyText = text.slice(fn.bodyStart, fn.bodyEnd);
    const lines = bodyText.split('\n');

    let offsetInBody = 0;
    const lineOffsets: number[] = [];
    for (let i = 0; i < lines.length; i++) {
      lineOffsets.push(offsetInBody);
      offsetInBody += lines[i].length + 1;
    }

    const varPattern = /\$([A-Za-z_][A-Za-z0-9_]*)\b/gu;
    const definitions = new Map<string, number>();
    const unsetNames = new Set<string>();
    const references: Array<{ name: string; startOffset: number; endOffset: number; line: number }> = [];

    for (const param of fn.params) {
      definitions.set(param, -1);
    }

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      const lineStart = fn.bodyStart + lineOffsets[lineIdx];

      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
        continue;
      }

      const unsetMatch = /\bunset\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)/gu.exec(line);
      if (unsetMatch) {
        unsetNames.add(unsetMatch[1]);
      }

      const foreachStart = line.search(/\bforeach\s+\(/u);
      if (foreachStart >= 0) {
        const parenPos = lineStart + line.indexOf('(', foreachStart);
        const closeParen = findMatchingDelimiter(text, parenPos, '(', ')');
        if (closeParen >= 0) {
          const foreachText = text.slice(parenPos, closeParen + 1);
          const valMatch = /\s+as\s+(?:\$[A-Za-z_][\w]*\s*=>\s*)?\$([A-Za-z_][A-Za-z0-9_]*)/u.exec(foreachText);
          if (valMatch) {
            definitions.set(valMatch[1], lineIdx);
          }
          const keyMatch = /\s+as\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*=>/u.exec(foreachText);
          if (keyMatch) {
            definitions.set(keyMatch[1], lineIdx);
          }
        }
      }

      const catchMatch = /\bcatch\s*\([^)]*\)/gu.exec(line);
      if (catchMatch) {
        const catchText = catchMatch[0];
        const varMatch = /\$([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(catchText);
        if (varMatch) {
          definitions.set(varMatch[1], lineIdx);
        }
      }

      const globalMatch = /\bglobal\s+\$([A-Za-z_][A-Za-z0-9_]*)\b/gu;
      for (const gm of line.matchAll(globalMatch)) {
        if (gm[1]) definitions.set(gm[1], lineIdx);
      }

      const staticDeclMatch = /\bstatic\s+\$([A-Za-z_][A-Za-z0-9_]*)\s*[=;]/gu;
      for (const sm of line.matchAll(staticDeclMatch)) {
        if (sm[1]) definitions.set(sm[1], lineIdx);
      }

      const listMatch = /\blist\s*\(/gu;
      if (listMatch.test(line)) {
        const listContent = line.slice(line.indexOf('(') + 1, line.lastIndexOf(')'));
        const listVarPattern = /\$([A-Za-z_][A-Za-z0-9_]*)\b/gu;
        for (const lm of listContent.matchAll(listVarPattern)) {
          if (lm[1]) definitions.set(lm[1], lineIdx);
        }
      }

      const PHP_PSEUDO_VARS = new Set([
        'this', 'GLOBALS', '_SERVER', '_GET', '_POST', '_REQUEST',
        '_SESSION', '_COOKIE', '_FILES', '_ENV',
      ]);

      let varMatch: RegExpExecArray | null;
      const localVarPattern = /\$([A-Za-z_][A-Za-z0-9_]*)\b/gu;
      while ((varMatch = localVarPattern.exec(line)) !== null) {
        const varName = varMatch[1];
        const localOffset = varMatch.index;
        const globalOffset = lineStart + localOffset;

        if (PHP_PSEUDO_VARS.has(varName)) continue;

        const beforeChar = localOffset > 0 ? line[localOffset - 1] : '';
        if (beforeChar === '$' || beforeChar === '{') continue;

        const afterSlice = line.slice(localOffset + varMatch[0].length).trimStart();
        const isAssignment = afterSlice.startsWith('=') && !afterSlice.startsWith('==') && !afterSlice.startsWith('===');

        if (isAssignment) {
          definitions.set(varName, lineIdx);
        } else {
          references.push({
            name: varName,
            startOffset: globalOffset,
            endOffset: globalOffset + varMatch[0].length,
            line: lineIdx,
          });
        }
      }
    }

    for (const ref of references) {
      const defLine = definitions.get(ref.name);
      if (defLine !== undefined && defLine >= 0 && defLine <= ref.line) {
        continue;
      }
      if (defLine === -1) continue;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: ref.startOffset,
          endOffset: ref.endOffset,
          text: `$${ref.name}`,
        }),
      );
    }

    if (fn.isStatic) {
      const thisPattern = /\$this\s*->/gu;
      for (const thisMatch of findAllMatches(bodyText, thisPattern)) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: fn.bodyStart + thisMatch.startOffset,
            endOffset: fn.bodyStart + thisMatch.endOffset,
            text: '$this->',
          }),
        );
      }
    }

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      const unsetExec = /\bunset\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\)/u.exec(line);
      if (!unsetExec) continue;

      const unsetVar = unsetExec[1];
      const afterLineText = lines.slice(lineIdx + 1).join('\n');
      const afterPattern = new RegExp(`\\$${escapeRegExp(unsetVar)}\\b`, 'u');
      const afterMatch = afterPattern.exec(afterLineText);
      if (afterMatch) {
        const afterAbsolute = fn.bodyStart + lineOffsets[lineIdx] + lines[lineIdx].length + 1 + afterMatch.index;
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: afterAbsolute,
            endOffset: afterAbsolute + afterMatch[0].length,
            text: `$${unsetVar}`,
          }),
        );
      }
    }
  }

  return findings;
}

function collectInaccessiblePropertyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_CORRECTNESS_FACT_KINDS.inaccessibleProperty;
  const findings: ObservedFact[] = [];
  const classInfoList = collectPhpClassPropertyInfo(text);

  const thisAccessPattern = /\$this\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()/gu;
  for (const match of findAllMatches(text, thisAccessPattern)) {
    const propName = /\$this\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(match.matchedText)?.[1];
    if (!propName) continue;

    const pos = match.startOffset;
    let foundClass: ClassPropertyInfo | undefined;

    for (const ci of classInfoList) {
      if (pos > ci.openBrace && pos < ci.closeBrace) {
        foundClass = ci;
        break;
      }
    }

    if (!foundClass) continue;
    if (foundClass.hasMagicGetSet) continue;
    if (foundClass.properties.has(propName)) continue;

    if (foundClass.parentPrivateProps.has(propName)) {
      const accessStart = match.startOffset + match.matchedText.indexOf(`->${propName}`);
      const accessEnd = accessStart + propName.length + 2;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: accessStart,
          endOffset: accessEnd,
          text: `->${propName}`,
        }),
      );
    }
  }

  return findings;
}
