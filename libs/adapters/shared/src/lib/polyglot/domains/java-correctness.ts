import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches, findMatchingDelimiter } from '../../runtime';
import { createOffsetFact } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const JAVA_CORRECTNESS_FACT_KINDS = {
  emptyCatch: 'java.correctness.empty-catch',
  equalsOnArray: 'java.correctness.equals-on-array',
  syncOnStringLiteral: 'java.correctness.sync-on-string-literal',
  catchNullPointer: 'java.correctness.catch-null-pointer',
  unsafeOptionalGet: 'java.correctness.unsafe-optional-get',
  returnInFinally: 'java.correctness.return-in-finally',
  unconditionalRecursion: 'java.correctness.unconditional-recursion',
  doubleCheckedLocking: 'java.correctness.double-checked-locking',
  streamReuse: 'java.correctness.stream-reuse',
  arrayIndexBounds: 'java.correctness.array-index-bounds',
  syncOnGetClass: 'java.correctness.sync-on-get-class',
  optionalNull: 'java.correctness.optional-null',
  stringBuilderCharCtor: 'java.correctness.stringbuilder-char-ctor',
  staticDateField: 'java.correctness.static-date-field',
  unescapedWhitespace: 'java.correctness.unescaped-whitespace',
  unsupportedJdkApi: 'java.correctness.unsupported-jdk-api',
  nanComparison: 'java.correctness.nan-comparison',
  readResolveReturnType: 'java.correctness.read-resolve-return-type',
  serializationMethodSignature: 'java.correctness.serialization-method-signature',
  serializableSuperclass: 'java.correctness.serializable-superclass',
  collectionRemoveTypeMismatch: 'java.correctness.collection-remove-type-mismatch',
  unsafeCollectionDowncast: 'java.correctness.unsafe-collection-downcast',
  annotationCheckAlwaysFalse: 'java.correctness.annotation-check-always-false',
  unimplementableInterface: 'java.correctness.unimplementable-interface',
  invalidSerialVersionUid: 'java.correctness.invalid-serial-version-uid',
  hashCodeOnArray: 'java.correctness.hashcode-on-array',
  loopConditionNeverTrue: 'java.correctness.loop-condition-never-true',
  nonTerminatingLoop: 'java.correctness.non-terminating-loop',
  unsupportedMethodCall: 'java.correctness.unsupported-method-call',
  syncOnMutableRef: 'java.correctness.sync-on-mutable-ref',
  unsyncStaticLazyInit: 'java.correctness.unsync-static-lazy-init',
  boxedBooleanConditional: 'java.correctness.boxed-boolean-conditional',
  syncOnNullableField: 'java.correctness.sync-on-nullable-field',
  syncOnPublicField: 'java.correctness.sync-on-public-field',
  threadStaticMisuse: 'java.correctness.thread-static-misuse',
  doubleAssignment: 'java.correctness.double-assignment',
  invalidTimeConstants: 'java.correctness.invalid-time-constants',
  comparatorDowncastSignFlip: 'java.correctness.comparator-downcast-sign-flip',
  cacheloaderNullReturn: 'java.correctness.cacheloader-null-return',
  incorrectMainSignature: 'java.correctness.incorrect-main-signature',
  enumGetClass: 'java.correctness.enum-get-class',
  deprecatedThreadMethods: 'java.correctness.deprecated-thread-methods',

  // Batch 19 (JAVA-E) — bug risk / framework rules
  possibleNullAccess: 'java.correctness.possible-null-access',
  possibleNullAccessException: 'java.correctness.possible-null-access-exception',
  invalidatedIterator: 'java.correctness.invalidated-iterator',
  mutableDataExposed: 'java.correctness.mutable-data-exposed',
  durationWithNanosMisuse: 'java.correctness.duration-with-nanos-misuse',
  indexOfReversedArguments: 'java.correctness.indexof-reversed-arguments',
  nCopiesArgumentOrder: 'java.correctness.ncopies-argument-order',
  classIsInstanceOnClass: 'java.correctness.class-isinstance-on-class',

  // Batch 15 (JAVA-E) — bug risk / framework rules
  zoneIdInvalidTimezone: 'java.correctness.zoneid-invalid-timezone',
  timezoneInvalidId: 'java.correctness.timezone-invalid-id',
  instantUnsupportedTemporalUnit: 'java.correctness.instant-unsupported-temporal-unit',
  iterablePathType: 'java.correctness.iterable-path-type',
  throwNull: 'java.correctness.throw-null',
  hashtableContainsValue: 'java.correctness.hashtable-contains-value',

  // Batch 21 (JAVA-S) — correctness / system-exit
  systemExit: 'java.correctness.system-exit',

  // Batch 22 (JAVA-E) — unterminated assertion chain
  unterminatedAssertChain: 'java.correctness.unterminated-assertion-chain',

  // Batch 24 (JAVA-S) — security / correctness facts
  preparedStatementInLoop: 'java.correctness.prepared-statement-in-loop',
  assertionInProduction: 'java.correctness.assertion-in-production',
  arrayComparedToNonArray: 'java.correctness.array-compared-to-non-array',
  parameterReassignment: 'java.correctness.parameter-reassignment',
} as const;

export interface CollectJavaCorrectnessFactsOptions {
  text: string;
  detector: string;
}

export function collectJavaCorrectnessFacts(
  options: CollectJavaCorrectnessFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectEmptyCatchFacts(text, detector),
    ...collectEqualsOnArrayFacts(text, detector),
    ...collectSyncOnStringLiteralFacts(text, detector),
    ...collectCatchNullPointerFacts(text, detector),
    ...collectUnsafeOptionalGetFacts(text, detector),
    ...collectReturnInFinallyFacts(text, detector),
    ...collectUnconditionalRecursionFacts(text, detector),
    ...collectDoubleCheckedLockingFacts(text, detector),
    ...collectStreamReuseFacts(text, detector),
    ...collectArrayIndexBoundsFacts(text, detector),
    ...collectSyncOnGetClassFacts(text, detector),
    ...collectOptionalNullFacts(text, detector),
    ...collectStringBuilderCharCtorFacts(text, detector),
    ...collectStaticDateFieldFacts(text, detector),
    ...collectUnescapedWhitespaceFacts(text, detector),
    ...collectUnsupportedJdkApiFacts(text, detector),
    ...collectNanComparisonFacts(text, detector),
    ...collectReadResolveReturnTypeFacts(text, detector),
    ...collectSerializationMethodSignatureFacts(text, detector),
    ...collectSerializableSuperclassFacts(text, detector),
    ...collectCollectionRemoveTypeMismatchFacts(text, detector),
    ...collectUnsafeCollectionDowncastFacts(text, detector),
    ...collectAnnotationCheckAlwaysFalseFacts(text, detector),
    ...collectUnimplementableInterfaceFacts(text, detector),
    ...collectInvalidSerialVersionUidFacts(text, detector),
    ...collectHashCodeOnArrayFacts(text, detector),
    ...collectLoopConditionNeverTrueFacts(text, detector),
    ...collectNonTerminatingLoopFacts(text, detector),
    ...collectUnsupportedMethodCallFacts(text, detector),
    ...collectSyncOnMutableRefFacts(text, detector),
    ...collectUnsyncStaticLazyInitFacts(text, detector),
    ...collectBoxedBooleanConditionalFacts(text, detector),
    ...collectSyncOnNullableFieldFacts(text, detector),
    ...collectSyncOnPublicFieldFacts(text, detector),
    ...collectThreadStaticMisuseFacts(text, detector),
    ...collectDoubleAssignmentFacts(text, detector),
    ...collectInvalidTimeConstantsFacts(text, detector),
    ...collectComparatorDowncastSignFlipFacts(text, detector),
    ...collectCacheloaderNullReturnFacts(text, detector),
    ...collectIncorrectMainSignatureFacts(text, detector),
    ...collectEnumGetClassFacts(text, detector),
    ...collectDeprecatedThreadMethodsFacts(text, detector),

    // Batch 19 (JAVA-E) — bug risk / framework facts
    ...collectPossibleNullAccessFacts(text, detector),
    ...collectPossibleNullAccessExceptionFacts(text, detector),
    ...collectInvalidatedIteratorFacts(text, detector),
    ...collectMutableDataExposedFacts(text, detector),
    ...collectDurationWithNanosMisuseFacts(text, detector),
    ...collectIndexOfReversedArgumentsFacts(text, detector),
    ...collectNCopiesArgumentOrderFacts(text, detector),
    ...collectClassIsInstanceOnClassFacts(text, detector),

    // Batch 15 (JAVA-E) — bug risk / framework facts
    ...collectZoneIdInvalidTimezoneFacts(text, detector),
    ...collectTimezoneInvalidIdFacts(text, detector),
    ...collectInstantUnsupportedTemporalUnitFacts(text, detector),
    ...collectIterablePathTypeFacts(text, detector),
    ...collectThrowNullFacts(text, detector),
    ...collectHashtableContainsValueFacts(text, detector),

    // Batch 21 (JAVA-S) — correctness / system-exit
    ...collectSystemExitFacts(text, detector),

    // Batch 22 (JAVA-E) — unterminated assertion chain
    ...collectUnterminatedAssertChainFacts(text, detector),

    // Batch 24 (JAVA-S) — security / correctness facts
    ...collectPreparedStatementInLoopFacts(text, detector),
    ...collectAssertionInProductionFacts(text, detector),
    ...collectArrayComparedToNonArrayFacts(text, detector),
    ...collectParameterReassignmentFacts(text, detector),
  ];
}

function collectEmptyCatchFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.emptyCatch,
    appliesTo: 'block',
    pattern:
      /\bcatch\s*\([^)]*\)\s*\{\s*(?:\/\/[^\n]*\s*|\/\*[\s\S]*?\*\/\s*)*\}/gu,
  });
}

function collectSyncOnStringLiteralFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.syncOnStringLiteral,
    appliesTo: 'block',
    pattern: /\bsynchronized\s*\(\s*(?:"[^"\n]*"|'[^'\n]*')\s*\)/gu,
  });
}

function collectCatchNullPointerFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.catchNullPointer,
    appliesTo: 'block',
    pattern: /\bcatch\s*\(\s*NullPointerException\b[^)]*\)/gu,
  });
}

function collectEqualsOnArrayFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const arrayNames = collectArrayVariableNames(text);

  if (arrayNames.size === 0) {
    return [];
  }

  const kind = JAVA_CORRECTNESS_FACT_KINDS.equalsOnArray;
  const findings: ObservedFact[] = [];

  for (const name of arrayNames) {
    const callPattern = new RegExp(
      `(?<![A-Za-z_$0-9.])${escapeRegex(name)}\\.equals\\s*\\(`,
      'gu',
    );

    for (const match of findAllMatches(text, callPattern)) {
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

function collectUnsafeOptionalGetFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const optionalNames = collectOptionalVariableNames(text);

  if (optionalNames.size === 0) {
    return [];
  }

  const kind = JAVA_CORRECTNESS_FACT_KINDS.unsafeOptionalGet;
  const findings: ObservedFact[] = [];
  const lineOffsets = computeLineOffsets(text);

  for (const name of optionalNames) {
    const getPattern = new RegExp(
      `(?<![A-Za-z_$0-9.])${escapeRegex(name)}\\.get\\s*\\(\\s*\\)`,
      'gu',
    );
    const guardPattern = new RegExp(
      `(?<![A-Za-z_$0-9.])${escapeRegex(
        name,
      )}\\.(?:isPresent|isEmpty|ifPresent|ifPresentOrElse|orElse|orElseGet|orElseThrow|map|flatMap|filter)\\b`,
      'gu',
    );

    const guardMatches = findAllMatches(text, guardPattern);
    const guardLines = new Set<number>(
      guardMatches.map((guard) => offsetToLine(guard.startOffset, lineOffsets)),
    );

    for (const match of findAllMatches(text, getPattern)) {
      const line = offsetToLine(match.startOffset, lineOffsets);
      const hasNearbyGuard = Array.from(guardLines).some(
        (guardLine) => Math.abs(guardLine - line) <= 3,
      );

      if (hasNearbyGuard) {
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
  }

  return findings;
}

function collectReturnInFinallyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.returnInFinally;
  const findings: ObservedFact[] = [];

  for (const match of text.matchAll(/\bfinally\s*\{/gu)) {
    const openIndex = (match.index ?? -1) + match[0].length - 1;

    if (openIndex < 0) {
      continue;
    }

    const closeIndex = findMatchingDelimiter(text, openIndex, '{', '}');

    if (closeIndex < 0) {
      continue;
    }

    const innerText = text.slice(openIndex + 1, closeIndex);
    const controlPattern = /\b(?:return|break|continue|throw)\b/gu;
    const cleanedInner = stripNestedBlocks(innerText);

    for (const innerMatch of cleanedInner.matchAll(controlPattern)) {
      const innerStart = innerMatch.index ?? 0;
      const absoluteStart = openIndex + 1 + innerStart;
      const absoluteEnd = absoluteStart + innerMatch[0].length;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteEnd,
          text: innerMatch[0],
        }),
      );
    }
  }

  return findings;
}

function collectSyncOnGetClassFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.syncOnGetClass,
    appliesTo: 'block',
    pattern: /\bsynchronized\s*\([^)]*\bgetClass\s*\(\s*\)[^)]*\)/gu,
  });
}

function collectStringBuilderCharCtorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.stringBuilderCharCtor,
    appliesTo: 'block',
    pattern: /\bnew\s+(?:StringBuilder|StringBuffer)\s*\(\s*'[^']*'\s*\)/gu,
  });
}

function collectStaticDateFieldFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.staticDateField,
    appliesTo: 'block',
    pattern:
      /(?:public|protected)\s+static\s+(?:final\s+)?(?:SimpleDateFormat|DateFormat|Calendar|java\.util\.Date|java\.text\.SimpleDateFormat|java\.text\.DateFormat|java\.util\.Calendar)\s+\w+/gu,
  });
}

function collectArrayIndexBoundsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.arrayIndexBounds;
  const findings: ObservedFact[] = [];

  const patterns: RegExp[] = [
    /\b(\w+)\s*\[\s*\1\.length\s*\]/gu,
    /\b(\w+)\.get\s*\(\s*\1\.size\s*\(\s*\)\s*\)/gu,
    /\b(\w+)\.charAt\s*\(\s*\1\.length\s*\(\s*\)\s*\)/gu,
  ];

  for (const pattern of patterns) {
    for (const match of findAllMatches(text, pattern)) {
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

function collectStreamReuseFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const streamNames = collectStreamVariableNames(text);

  if (streamNames.size === 0) {
    return [];
  }

  const kind = JAVA_CORRECTNESS_FACT_KINDS.streamReuse;
  const findings: ObservedFact[] = [];
  const terminalOps =
    /\.(?:collect|forEach|toArray|toList|reduce|count|findFirst|findAny|anyMatch|allMatch|noneMatch|min|max|sum|average|summaryStatistics|iterator|spliterator)\s*\(/gu;

  for (const name of streamNames) {
    const usagePattern = new RegExp(
      `(?<![A-Za-z_$0-9.])${escapeRegex(name)}${terminalOps.source}`,
      'gu',
    );

    const matches = findAllMatches(text, usagePattern);

    if (matches.length >= 2) {
      for (let i = 1; i < matches.length; i++) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: matches[i].startOffset,
            endOffset: matches[i].endOffset,
            text: matches[i].matchedText,
          }),
        );
      }
    }
  }

  return findings;
}

function collectOptionalNullFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.optionalNull;
  const findings: ObservedFact[] = [];

  const optionalReturnNames = collectOptionalReturnTypeMethods(text);

  const nullAssignPattern =
    /(\w+)\s*=\s*(?:null|getNullOptional\s*\(\s*\))\s*;/gu;
  for (const match of findAllMatches(text, nullAssignPattern)) {
    const varName = match.matchedText.match(/(\w+)\s*=\s*/);
    if (varName && isOptionalTyped(text, varName[1])) {
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

  const methodOpenPattern =
    /(?:(?:public|protected|private|static|final|abstract|synchronized|native)\s+)*Optional(?:<[^<>;\n]+>)?\s+\w+\s*\(/gu;

  for (const match of text.matchAll(methodOpenPattern)) {
    const bodyOpen = match.index! + match[0].length;

    if (bodyOpen < 0) {
      continue;
    }

    const parenClose = findMatchingDelimiter(text, bodyOpen - 1, '(', ')');

    if (parenClose < 0) {
      continue;
    }

    const afterParen = text.slice(parenClose + 1);
    const braceIndex = afterParen.search(/\{/);

    if (braceIndex < 0) {
      continue;
    }

    const braceOpen = parenClose + 1 + braceIndex;
    const braceClose = findMatchingDelimiter(text, braceOpen, '{', '}');

    if (braceClose < 0) {
      continue;
    }

    const bodyText = text.slice(braceOpen + 1, braceClose);
    const returnNullPattern = /\breturn\s+null\b/g;

    for (const nullMatch of bodyText.matchAll(returnNullPattern)) {
      const absoluteStart = braceOpen + 1 + (nullMatch.index ?? 0);
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteStart + nullMatch[0].length,
          text: nullMatch[0],
        }),
      );
    }
  }

  return findings;
}

function collectUnconditionalRecursionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.unconditionalRecursion;
  const findings: ObservedFact[] = [];

  const methodPattern =
    /(?:(?:public|protected|private|static|final|abstract|synchronized|native)\s+)*(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;

  for (const match of text.matchAll(methodPattern)) {
    const methodName = match[1];

    if (!methodName || methodName === 'main' || methodName === '<init>') {
      continue;
    }

    const openIndex = (match.index ?? 0) + match[0].lastIndexOf('{');

    if (openIndex < 0) {
      continue;
    }

    const closeIndex = findMatchingDelimiter(text, openIndex, '{', '}');

    if (closeIndex < 0) {
      continue;
    }

    const bodyText = text.slice(openIndex + 1, closeIndex);
    const cleanedBody = stripNestedBlocks(bodyText);

    const selfCallPattern = new RegExp(
      `(?:\\.\\s*${escapeRegex(methodName)}\\s*\\(|\\b${escapeRegex(methodName)}\\s*\\()`,
      'gu',
    );

    const calls = findAllMatches(cleanedBody, selfCallPattern);

    if (calls.length === 0) {
      continue;
    }

    const hasGuard = /\b(?:if|else\s+if|while|for)\b/.test(cleanedBody);

    if (!hasGuard) {
      for (const call of calls) {
        const absoluteStart = openIndex + 1 + call.startOffset;
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteStart + call.matchedText.length,
            text: call.matchedText,
          }),
        );
      }
    }
  }

  return findings;
}

function collectDoubleCheckedLockingFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.doubleCheckedLocking;
  const findings: ObservedFact[] = [];

  const syncPattern = /\bsynchronized\s*\([^)]*\)\s*\{/gu;

  for (const match of text.matchAll(syncPattern)) {
    const syncOpenIndex =
      (match.index ?? 0) + match[0].lastIndexOf('{');

    if (syncOpenIndex < 0) {
      continue;
    }

    const syncCloseIndex = findMatchingDelimiter(
      text,
      syncOpenIndex,
      '{',
      '}',
    );

    if (syncCloseIndex < 0) {
      continue;
    }

    const syncBody = text.slice(syncOpenIndex + 1, syncCloseIndex);
    const hasNullCheckInside =
      /\bif\s*\(\s*\w+\s*(?:==|!=)\s*null\s*\)/.test(syncBody);
    const hasAssignment = /\w+\s*=\s*new\s+\w+/.test(syncBody);

    if (!hasNullCheckInside || !hasAssignment) {
      continue;
    }

    const assignedField = syncBody.match(/(\w+)\s*=\s*new/);
    if (!assignedField) {
      continue;
    }

    const fieldName = assignedField[1];
    const hasVolatile = new RegExp(
      `\\bvolatile\\b[^;]*\\b${escapeRegex(fieldName)}\\b`,
      'g',
    ).test(text);

    if (hasVolatile) {
      continue;
    }

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.index ?? 0,
        endOffset: syncCloseIndex + 1,
        text: match[0],
      }),
    );
  }

  return findings;
}

function collectUnescapedWhitespaceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.unescapedWhitespace,
    appliesTo: 'block',
    pattern:
      /(?:Pattern\.compile|String\.(?:matches|replaceAll|replaceFirst|split))\s*\(\s*"[^"]*?(?<!\\)\\[nrtfb][^"]*"\s*\)/gu,
  });
}

function collectUnsupportedJdkApiFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.unsupportedJdkApi,
    appliesTo: 'block',
    pattern:
      /(?:^|\n)\s*import\s+(?:sun|com\.sun)\.[A-Za-z]\w*(?:\.[A-Za-z]\w*)*\s*;|\bsun\.misc\.Unsafe\b/gu,
  });
}

function collectNanComparisonFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.nanComparison,
    appliesTo: 'block',
    pattern:
      /(?:==|!=)\s*(?:Double|Float)\.NaN\b|\b(?:Double|Float)\.NaN\s*(?:==|!=)|\.equals\s*\(\s*(?:Double|Float)\.NaN\s*\)/gu,
  });
}

function collectReadResolveReturnTypeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.readResolveReturnType,
    appliesTo: 'block',
    pattern:
      /\b(?!Object\b|void\b)\w+\s+readResolve\s*\(/gu,
  });
}

function collectSerializationMethodSignatureFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.serializationMethodSignature;
  const findings: ObservedFact[] = [];

  const wrongAccessPattern =
    /(?:public|protected)\s+void\s+(writeObject|readObject|readObjectNoData)\s*\(/gu;
  for (const match of findAllMatches(text, wrongAccessPattern)) {
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

  const wrongReturnPattern =
    /\b(?!void\b)\w+\s+(writeObject|readObject)\s*\(/gu;
  for (const match of findAllMatches(text, wrongReturnPattern)) {
    const lineStart = text.lastIndexOf('\n', match.startOffset) + 1;
    const linePrefix = text.slice(lineStart, match.startOffset);
    if (/^\s*(?:public|protected|private)\s/.test(linePrefix)) {
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

  const readObjectNoDataWithParamsPattern =
    /\breadObjectNoData\s*\(\s*\w+/gu;
  for (const match of findAllMatches(text, readObjectNoDataWithParamsPattern)) {
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

function collectSerializableSuperclassFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.serializableSuperclass;
  const findings: ObservedFact[] = [];

  const serializableClassPattern =
    /\bclass\s+(\w+)\s+extends\s+(\w+)\s+implements\s+(?:.*\b)?Serializable\b/gu;
  for (const match of findAllMatches(text, serializableClassPattern)) {
    const parentName = match.matchedText.match(
      /\bextends\s+(\w+)/,
    )?.[1];
    if (!parentName) continue;

    const parentImplSerializable = new RegExp(
      `\\bclass\\s+${escapeRegex(parentName)}[^{]*implements[^{]*\\bSerializable\\b`,
      'gu',
    );
    if (parentImplSerializable.test(text)) continue;

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

function collectCollectionRemoveTypeMismatchFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.collectionRemoveTypeMismatch;
  const findings: ObservedFact[] = [];

  const collectionPattern =
    /\b(List|Set|Map|Collection|Queue|Deque)\s*<[^>]*>\s+(\w+)\b/gu;
  for (const decl of findAllMatches(text, collectionPattern)) {
    const typeArg = decl.matchedText.match(/<([^>]+)>/)?.[1] ?? '';
    const varName = decl.matchedText.match(/>\s*(\w+)$/)?.[1];
    if (!varName || /^\s*(?:Integer|Long|Double|Float|Boolean|Short|Byte|Character)\s*$/.test(typeArg)) continue;

    const removePattern = new RegExp(
      `\\b${escapeRegex(varName)}\\.remove\\s*\\(\\s*(\\d+)\\s*\\)`,
      'gu',
    );
    for (const call of findAllMatches(text, removePattern)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: call.startOffset,
          endOffset: call.endOffset,
          text: call.matchedText,
        }),
      );
    }
  }

  return findings;
}

function collectUnsafeCollectionDowncastFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.unsafeCollectionDowncast;
  const findings: ObservedFact[] = [];
  const lineOffsets = computeLineOffsets(text);

  const declPattern =
    /\b(List|Set|Map|Collection|Queue|Deque|Iterable)(?:<[^<>;\n]+>)?\s+(\w+)\b/gu;
  for (const decl of findAllMatches(text, declPattern)) {
    const varName = decl.matchedText.match(/>?\s*(\w+)$/)?.[1];
    if (!varName) continue;

    const castPattern = new RegExp(
      `\\((ArrayList|LinkedList|HashSet|TreeSet|HashMap|TreeMap|LinkedHashMap|ArrayDeque|PriorityQueue|ConcurrentHashMap|CopyOnWriteArrayList|Vector|Stack)(?:<[^>]*>)?\\)\\s*${escapeRegex(varName)}`,
      'gu',
    );

    for (const cast of findAllMatches(text, castPattern)) {
      const castLine = offsetToLine(cast.startOffset, lineOffsets);
      const lookbackStart = text.lastIndexOf('\n', cast.startOffset - 1) + 1;
      const lookbackText = text.slice(lookbackStart, cast.startOffset);
      const hasInstanceofOnLine =
        /\binstanceof\b/.test(lookbackText) ||
        (castLine > 0 &&
          /\binstanceof\b/.test(
            text.slice(
              text.lastIndexOf('\n', text.lastIndexOf('\n', cast.startOffset - 2) - 1) + 1,
              cast.startOffset,
            ),
          ));

      if (hasInstanceofOnLine || hasInstanceofOnLine) continue;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: cast.startOffset,
          endOffset: cast.endOffset,
          text: cast.matchedText,
        }),
      );
    }
  }

  return findings;
}

function collectAnnotationCheckAlwaysFalseFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.annotationCheckAlwaysFalse;
  const findings: ObservedFact[] = [];

  const retentionAnns = new Set<string>();
  const retentionPattern =
    /@Retention\s*\(\s*RetentionPolicy\.(SOURCE|CLASS)\s*\)[^@]*@interface\s+(\w+)/gu;
  for (const match of text.matchAll(retentionPattern)) {
    retentionAnns.add(match[2]);
  }

  if (retentionAnns.size === 0) return findings;

  for (const annName of retentionAnns) {
    const checkPattern = new RegExp(
      `\\.isAnnotationPresent\\s*\\(\\s*"${escapeRegex(annName)}"\\s*\\)`,
      'gu',
    );
    for (const match of findAllMatches(text, checkPattern)) {
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

function collectUnimplementableInterfaceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.unimplementableInterface;
  const findings: ObservedFact[] = [];

  const objectClashingMethods = new Set([
    'wait', 'notify', 'notifyAll', 'getClass', 'finalize',
  ]);

  const interfacePattern = /\binterface\s+(\w+)\s*\{/gu;
  for (const match of text.matchAll(interfacePattern)) {
    const openIndex = match.index! + match[0].length - 1;
    const closeIndex = findMatchingDelimiter(text, openIndex, '{', '}');
    if (closeIndex < 0) continue;

    const bodyText = text.slice(openIndex + 1, closeIndex);

    const methodPattern =
      /(?:(?:public|protected|private|static|final|abstract|default|synchronized)\s+)*(\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*\(/gu;
    for (const methodMatch of bodyText.matchAll(methodPattern)) {
      const returnType = methodMatch[1];
      const methodName = methodMatch[2];

      if (objectClashingMethods.has(methodName)) {
        const absoluteStart = openIndex + 1 + (methodMatch.index ?? 0);
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteStart + methodMatch[0].length,
            text: methodMatch[0],
          }),
        );
        continue;
      }

      if (methodName === 'toString' && returnType !== 'String') {
        const absoluteStart = openIndex + 1 + (methodMatch.index ?? 0);
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteStart + methodMatch[0].length,
            text: methodMatch[0],
          }),
        );
        continue;
      }

      if (methodName === 'clone') {
        const returnMatch = returnType.match(/^\w+/);
        if (returnMatch && returnMatch[0] !== 'Object') {
          const absoluteStart = openIndex + 1 + (methodMatch.index ?? 0);
          findings.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: absoluteStart,
              endOffset: absoluteStart + methodMatch[0].length,
              text: methodMatch[0],
            }),
          );
          continue;
        }
      }

      if (methodName === 'hashCode' && returnType !== 'int') {
        const absoluteStart = openIndex + 1 + (methodMatch.index ?? 0);
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteStart + methodMatch[0].length,
            text: methodMatch[0],
          }),
        );
      }
    }
  }

  return findings;
}

function collectInvalidSerialVersionUidFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.invalidSerialVersionUid,
    appliesTo: 'block',
    pattern:
      /\b(?:private|public|protected)?\s*(?:(?:(?:static|final)\s+)*(?!static\s+final\s+long\b)\w+\s+)?serialVersionUID\s*=\s*[^;]+;/gu,
    predicate: (match) => {
      const before = match.matchedText;
      return !/static\s+final\s+long\s+serialVersionUID/.test(before);
    },
  });
}

function collectHashCodeOnArrayFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const arrayNames = collectArrayVariableNames(text);
  if (arrayNames.size === 0) return [];

  const kind = JAVA_CORRECTNESS_FACT_KINDS.hashCodeOnArray;
  const findings: ObservedFact[] = [];

  for (const name of arrayNames) {
    const callPattern = new RegExp(
      `(?<![A-Za-z_$0-9.])${escapeRegex(name)}\\.hashCode\\s*\\(\\s*\\)`,
      'gu',
    );
    for (const match of findAllMatches(text, callPattern)) {
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

function collectLoopConditionNeverTrueFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.loopConditionNeverTrue;

  const patterns: RegExp[] = [
    /\bwhile\s*\(\s*false\s*\)/gu,
    /\bfor\s*\(\s*;?\s*false\s*;?[^)]*\)/gu,
    /\bwhile\s*\(\s*true\s*&&\s*false\s*\)/gu,
  ];

  for (const pattern of patterns) {
    for (const match of findAllMatches(text, pattern)) {
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

function collectNonTerminatingLoopFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.nonTerminatingLoop;
  const findings: ObservedFact[] = [];

  const loopPatterns: RegExp[] = [
    /\bwhile\s*\(\s*true\s*\)\s*\{/gu,
    /\bfor\s*\(\s*;\s*;\s*\)\s*\{/gu,
  ];

  for (const pattern of loopPatterns) {
    for (const match of text.matchAll(pattern)) {
      const openIndex = (match.index ?? 0) + match[0].lastIndexOf('{');
      if (openIndex < 0) continue;

      const closeIndex = findMatchingDelimiter(text, openIndex, '{', '}');
      if (closeIndex < 0) continue;

      const bodyText = text.slice(openIndex + 1, closeIndex);
      const cleanedBody = stripNestedBlocks(bodyText);

      const hasExit = /\b(?:break|return|System\.exit)\b/.test(cleanedBody);
      if (hasExit) continue;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.index ?? 0,
          endOffset: closeIndex + 1,
          text: match[0],
        }),
      );
    }
  }

  return findings;
}

function collectUnsupportedMethodCallFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.unsupportedMethodCall;
  const findings: ObservedFact[] = [];

  const throwingMethods = new Map<string, number>();

  const methodPattern =
    /(?:(?:public|protected|private|static|final|abstract|synchronized|native)\s+)*(\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;
  for (const match of text.matchAll(methodPattern)) {
    const methodName = match[2];
    const openIndex = (match.index ?? 0) + match[0].lastIndexOf('{');
    if (openIndex < 0) continue;

    const closeIndex = findMatchingDelimiter(text, openIndex, '{', '}');
    if (closeIndex < 0) continue;

    const bodyText = text.slice(openIndex + 1, closeIndex);
    if (!/\bUnsupportedOperationException\b/.test(bodyText)) continue;

    const methodLine = text.slice(
      text.lastIndexOf('\n', match.index! - 1) + 1,
      (match.index ?? 0) + match[0].length,
    );

    if (/\bfinal\b/.test(methodLine)) {
      throwingMethods.set(methodName, match.index ?? 0);
      continue;
    }

    const classPattern =
      /\bclass\s+(\w+)\s*(?:extends\s+\w+\s*)?(?:implements[^{]*)?\{/gu;
    for (const cls of text.matchAll(classPattern)) {
      const clsOpen = (cls.index ?? 0) + cls[0].lastIndexOf('{');
      const clsClose = findMatchingDelimiter(text, clsOpen, '{', '}');
      if (match.index! >= clsOpen && match.index! < clsClose) {
        const classLine = text.slice(
          text.lastIndexOf('\n', cls.index! - 1) + 1,
          clsOpen,
        );
        if (/\bfinal\s+class\b/.test(classLine)) {
          throwingMethods.set(methodName, match.index ?? 0);
        }
        break;
      }
    }
  }

  if (throwingMethods.size === 0) return findings;

  for (const [methodName, methodOffset] of throwingMethods) {
    const callPattern = new RegExp(
      `(?<![A-Za-z_$0-9.])${escapeRegex(methodName)}\\s*\\(`,
      'gu',
    );
    for (const call of findAllMatches(text, callPattern)) {
      if (call.startOffset === methodOffset) continue;

      const lineStart = text.lastIndexOf('\n', call.startOffset) + 1;
      const linePrefix = text.slice(lineStart, call.startOffset);
      if (/\w+\s*$/.test(linePrefix.trim())) continue;

      const callMethod = findEnclosingMethod(text, call.startOffset);
      if (callMethod === methodName) continue;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: call.startOffset,
          endOffset: call.endOffset,
          text: call.matchedText,
        }),
      );
    }
  }

  return findings;
}

function collectNonFinalInstanceFields(text: string): Set<string> {
  const fields = new Set<string>();
  const fieldPattern =
    /(?:private|protected|public)\s+(?!static\b)(?!final\b)(?:\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*[=;]/gu;
  for (const match of text.matchAll(fieldPattern)) {
    fields.add(match[1]);
  }
  return fields;
}

function collectAllInstanceFields(text: string): Map<string, { access: string; isFinal: boolean }> {
  const fields = new Map<string, { access: string; isFinal: boolean }>();
  const fieldPattern =
    /(?:private|protected|public)\s+(?:(static)\s+)?(?:(final)\s+)?(\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*[=;]/gu;
  for (const match of text.matchAll(fieldPattern)) {
    const access = match[0].startsWith('public') ? 'public' : match[0].startsWith('protected') ? 'protected' : 'private';
    const isFinal = !!match[2];
    fields.set(match[4], { access, isFinal });
  }
  return fields;
}

function collectSyncOnMutableRefFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.syncOnMutableRef;
  const allFields = collectAllInstanceFields(text);
  const nonFinalFields = Array.from(allFields.entries())
    .filter(([_, info]) => !info.isFinal && !info.access.startsWith('public'))
    .map(([name]) => name);
  const findings: ObservedFact[] = [];

  if (nonFinalFields.length === 0) return findings;

  for (const fieldName of nonFinalFields) {
    const syncPattern = new RegExp(
      `\\bsynchronized\\s*\\(\\s*(?:this\\.)?${escapeRegex(fieldName)}\\s*\\)`,
      'gu',
    );
    for (const match of findAllMatches(text, syncPattern)) {
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

function collectUnsyncStaticLazyInitFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.unsyncStaticLazyInit;
  const findings: ObservedFact[] = [];

  const staticFieldPattern = /\bstatic\s+(?:\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*;/gu;
  for (const decl of text.matchAll(staticFieldPattern)) {
    const fieldName = decl[1];

    const lazyInitPattern = new RegExp(
      `\\bif\\s*\\(\\s*${escapeRegex(fieldName)}\\s*==\\s*null\\s*\\)\\s*\\{`,
      'gu',
    );
    for (const initMatch of text.matchAll(lazyInitPattern)) {
      const braceIndex = (initMatch.index ?? 0) + initMatch[0].length - 1;
      const bodyClose = findMatchingDelimiter(text, braceIndex, '{', '}');
      if (bodyClose < 0) continue;

      const beforeText = text.slice(0, initMatch.index ?? 0);
      const lastBrace = beforeText.lastIndexOf('{');
      const beforeBlock = beforeText.slice(Math.max(0, lastBrace - 100), lastBrace);

      if (/\bsynchronized\s*\(/.test(beforeBlock)) continue;

      const methodDecl = beforeText.match(
        /(?:(?:public|protected|private|static|final|abstract|synchronized|native)\s+)*(?:\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+\w+\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{[^{]*$/u,
      );
      if (methodDecl && /\bsynchronized\b/.test(methodDecl[0])) continue;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: initMatch.index ?? 0,
          endOffset: bodyClose + 1,
          text: initMatch[0],
        }),
      );
    }
  }

  return findings;
}

function collectBoxedBooleanVariableNames(text: string): Set<string> {
  const names = new Set<string>();
  const declPattern = /\bBoolean\s+(?!\[\])(\w+)\s*[=;]/gu;
  for (const match of text.matchAll(declPattern)) {
    names.add(match[1]);
  }
  return names;
}

function collectBoxedBooleanConditionalFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.boxedBooleanConditional;
  const findings: ObservedFact[] = [];

  const booleanVars = collectBoxedBooleanVariableNames(text);
  if (booleanVars.size === 0) return findings;

  const lineOffsets = computeLineOffsets(text);

  for (const varName of booleanVars) {
    const safePattern = new RegExp(
      `${escapeRegex(varName)}\\s*(?:!=|==)\\s*null|Boolean\\.TRUE\\.equals\\s*\\(\\s*${escapeRegex(varName)}\\s*\\)|${escapeRegex(varName)}\\.booleanValue\\s*\\(`,
      'gu',
    );
    const safeMatches = findAllMatches(text, safePattern);
    const safeLines = new Set<number>(
      safeMatches.map((m) => offsetToLine(m.startOffset, lineOffsets)),
    );

    const conditionalPattern = new RegExp(
      `(?:if|while)\\s*\\(\\s*(?:!\\s*)?${escapeRegex(varName)}\\s*\\)|${escapeRegex(varName)}\\s*\\?`,
      'gu',
    );
    for (const match of findAllMatches(text, conditionalPattern)) {
      const line = offsetToLine(match.startOffset, lineOffsets);
      let isSafe = false;
      for (const safeLine of safeLines) {
        if (Math.abs(safeLine - line) <= 2) {
          isSafe = true;
          break;
        }
      }
      if (isSafe) continue;

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

function collectSyncOnNullableFieldFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.syncOnNullableField;
  const findings: ObservedFact[] = [];

  const nullableFields = new Set<string>();
  const fieldPattern = /(?:private|protected|public)\s+(?!static\b)(?:\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*;/gu;
  for (const match of text.matchAll(fieldPattern)) {
    nullableFields.add(match[1]);
  }

  const lineOffsets = computeLineOffsets(text);

  for (const fieldName of nullableFields) {
    const syncPattern = new RegExp(
      `\\bsynchronized\\s*\\(\\s*(?:this\\.)?${escapeRegex(fieldName)}\\s*\\)`,
      'gu',
    );
    for (const match of findAllMatches(text, syncPattern)) {
      const matchLine = offsetToLine(match.startOffset, lineOffsets);

      const lookbackStart = text.lastIndexOf('\n', Math.max(0, match.startOffset - 1)) + 1;
      const precedingText = text.slice(Math.max(0, lookbackStart - 120), lookbackStart);

      if (/Objects\.requireNonNull\s*\(/.test(precedingText)) continue;

      const nullGuardPattern = new RegExp(
        `\\bif\\s*\\(\\s*${escapeRegex(fieldName)}\\s*!=\\s*null\\s*\\)`,
        'gu',
      );
      const nullGuards = findAllMatches(text, nullGuardPattern);
      let hasNearbyGuard = false;
      for (const guard of nullGuards) {
        const guardLine = offsetToLine(guard.startOffset, lineOffsets);
        if (Math.abs(guardLine - matchLine) <= 3) {
          hasNearbyGuard = true;
          break;
        }
      }
      if (hasNearbyGuard) continue;

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

function collectSyncOnPublicFieldFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.syncOnPublicField;
  const findings: ObservedFact[] = [];

  const publicFields = new Set<string>();
  const fieldPattern = /\bpublic\s+(?:(?:static|final)\s+)*(?:\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*[=;]/gu;
  for (const match of text.matchAll(fieldPattern)) {
    const name = match[1];
    if (/^[A-Z_]+$/.test(name)) continue;
    publicFields.add(name);
  }

  if (publicFields.size === 0) return findings;

  for (const fieldName of publicFields) {
    const syncPattern = new RegExp(
      `\\bsynchronized\\s*\\(\\s*(?:this\\.|\\w+\\.)?${escapeRegex(fieldName)}\\s*\\)`,
      'gu',
    );
    for (const match of findAllMatches(text, syncPattern)) {
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

function collectThreadStaticMisuseFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.threadStaticMisuse;
  const staticMethods = /sleep|yield|interrupted|holdsLock|dumpStack/;
  const findings: ObservedFact[] = [];

  const pattern = /(\w+)\.(sleep|yield|interrupted|holdsLock|dumpStack)\s*\(/gu;
  for (const match of findAllMatches(text, pattern)) {
    const receiver = match.matchedText.match(/(\w+)\./)?.[1];
    if (!receiver || receiver === 'Thread' || receiver === 'Threads') continue;

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

function collectDoubleAssignmentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.doubleAssignment;
  const findings: ObservedFact[] = [];

  const methodPattern =
    /(?:(?:public|protected|private|static|final|abstract|synchronized|native)\s+)*(\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;

  for (const method of text.matchAll(methodPattern)) {
    const openIndex = (method.index ?? 0) + method[0].lastIndexOf('{');
    if (openIndex < 0) continue;

    const closeIndex = findMatchingDelimiter(text, openIndex, '{', '}');
    if (closeIndex < 0) continue;

    const bodyText = text.slice(openIndex + 1, closeIndex);

    const declPattern = /\b(\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*=/gu;
    const assignments = new Map<string, number[]>();

    for (const decl of bodyText.matchAll(declPattern)) {
      assignments.set(decl[2], []);
    }

    const assignPattern = /(\w+)\s*=\s*[^;]+;/gu;
    let lastMatch: RegExpExecArray | null = null;
    let match: RegExpExecArray | null;

    while ((match = assignPattern.exec(bodyText)) !== null) {
      const varName = match[1];
      if (!assignments.has(varName) && !lastMatch) {
        lastMatch = match;
        continue;
      }

      if (assignments.has(varName)) {
        assignments.get(varName)!.push((match.index ?? 0) + openIndex + 1);
      }
      lastMatch = match;
    }

    for (const [varName, offsets] of assignments) {
      if (offsets.length < 2) continue;

      for (let i = 1; i < offsets.length; i++) {
        const prevOffset = offsets[i - 1] - openIndex - 1;
        const currOffset = offsets[i] - openIndex - 1;
        const betweenText = bodyText.slice(
          prevOffset + bodyText.slice(prevOffset).indexOf(';') + 1,
          currOffset,
        );
        const varRefPattern = new RegExp(
          `(?<![A-Za-z_$0-9.])${escapeRegex(varName)}(?![A-Za-z_$0-9])`,
        );
        const noRead = !varRefPattern.test(betweenText.replace(/\b\w+\s*=\s*[^;]+;/g, ''));

        if (noRead) {
          const afterSemi = bodyText.indexOf(';', prevOffset) + 1;
          findings.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: openIndex + 1 + afterSemi,
              endOffset: openIndex + 1 + currOffset + bodyText.slice(currOffset).indexOf(';') + 1,
              text: bodyText.slice(afterSemi, currOffset + bodyText.slice(currOffset).indexOf(';') + 1),
            }),
          );
        }
      }
    }
  }

  return findings;
}

function collectInvalidTimeConstantsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.invalidTimeConstants;
  const findings: ObservedFact[] = [];

  const patterns: RegExp[] = [
    // LocalDate.of(year, month>12, day) - month > 12
    /\bLocalDate\.of\s*\(\s*\d+\s*,\s*(1[3-9]|[2-9]\d+)\s*,/gu,
    // LocalDate.of(year, month, day>31) - day > 31
    /\bLocalDate\.of\s*\(\s*\d+\s*,\s*\d+\s*,\s*([3-9]\d|[2-9]\d{2,})\s*\)/gu,
    // LocalTime.of(hour>=24, ...)
    /\bLocalTime\.of\s*\(\s*(2[4-9]|[3-9]\d+)\s*,/gu,
    // LocalTime.of(hour, minute>=60)
    /\bLocalTime\.of\s*\(\s*\d+\s*,\s*([6-9]\d|\d{3,})\s*(?:,|\))/gu,
    // LocalTime.of(hour, minute, second>=60)
    /\bLocalTime\.of\s*\(\s*\d+\s*,\s*\d+\s*,\s*([6-9]\d|\d{3,})\s*\)/gu,
    // MonthDay.of(month>12, day)
    /\bMonthDay\.of\s*\(\s*(1[3-9]|[2-9]\d+)\s*,/gu,
    // YearMonth.of(year, month>12)
    /\bYearMonth\.of\s*\(\s*\d+\s*,\s*(1[3-9]|[2-9]\d+)\s*\)/gu,
    // Duration.ofDays(0)
    /\bDuration\.ofDays\s*\(\s*0\s*\)/gu,
  ];

  for (const pattern of patterns) {
    for (const match of findAllMatches(text, pattern)) {
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

function collectComparatorDowncastSignFlipFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.comparatorDowncastSignFlip;
  const findings: ObservedFact[] = [];

  const methodPattern =
    /\b(?:compare|compareTo)\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;

  for (const match of text.matchAll(methodPattern)) {
    const openIndex = (match.index ?? 0) + match[0].lastIndexOf('{');
    if (openIndex < 0) continue;

    const closeIndex = findMatchingDelimiter(text, openIndex, '{', '}');
    if (closeIndex < 0) continue;

    const bodyText = text.slice(openIndex + 1, closeIndex);

    const castPattern =
      /\((?:short|byte|int)\)\s*\(\s*\w+\s*-\s*\w+\s*\)/gu;
    for (const cast of findAllMatches(bodyText, castPattern)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: openIndex + 1 + cast.startOffset,
          endOffset: openIndex + 1 + cast.endOffset,
          text: cast.matchedText,
        }),
      );
    }
  }

  return findings;
}

function collectCacheloaderNullReturnFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.cacheloaderNullReturn;
  const findings: ObservedFact[] = [];

  const classPattern =
    /\bclass\s+\w+\s+extends\s+(?:\w+(?:\.\w+)*\.)?CacheLoader(?:[<\s]|$)/gu;

  for (const cls of text.matchAll(classPattern)) {
    const clsOpen = (cls.index ?? 0) + cls[0].lastIndexOf('s') + 1;
    const realOpen = text.indexOf('{', cls.index ?? 0);
    if (realOpen < 0) continue;

    const clsClose = findMatchingDelimiter(text, realOpen, '{', '}');
    if (clsClose < 0) continue;

    const classBody = text.slice(realOpen + 1, clsClose);

    const loadMethodPattern =
      /(?:public|protected|private)?\s*(?:\w+(?:<[^>]*>)?)\s+load\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;

    for (const loadMatch of classBody.matchAll(loadMethodPattern)) {
      const loadOpen = classBody.indexOf('{', loadMatch.index ?? 0);
      if (loadOpen < 0) continue;

      const loadClose = findMatchingDelimiter(
        classBody,
        loadOpen,
        '{',
        '}',
      );
      if (loadClose < 0) continue;

      const loadBody = classBody.slice(loadOpen + 1, loadClose);

      const nullReturnPattern = /\breturn\s+null\b/gu;
      for (const nullMatch of findAllMatches(loadBody, nullReturnPattern)) {
        const absoluteStart =
          realOpen + 1 + loadOpen + 1 + nullMatch.startOffset;
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteStart + nullMatch.matchedText.length,
            text: nullMatch.matchedText,
          }),
        );
      }
    }
  }

  return findings;
}

function collectIncorrectMainSignatureFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.incorrectMainSignature;
  const findings: ObservedFact[] = [];

  const mainPattern =
    /(?:public|protected|private)?\s*(static)?\s*(\w+(?:\[\])*(?:\s*<[^>]*>)?)?\s+main\s*\(([^)]*)\)/gu;

  for (const match of text.matchAll(mainPattern)) {
    const isStatic = !!match[1];
    const returnType = match[2] ?? '';
    const params = (match[3] ?? '').trim();

    if (!isStatic || returnType !== 'void' || !/\bString\b/.test(params)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.index ?? 0,
          endOffset: (match.index ?? 0) + match[0].length,
          text: match[0],
        }),
      );
    }
  }

  return findings;
}

function collectEnumGetClassFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.enumGetClass;
  const findings: ObservedFact[] = [];

  const enumPattern = /\benum\s+\w+\s*\{/gu;

  for (const match of text.matchAll(enumPattern)) {
    const openIndex = (match.index ?? 0) + match[0].lastIndexOf('{');
    if (openIndex < 0) continue;

    const closeIndex = findMatchingDelimiter(text, openIndex, '{', '}');
    if (closeIndex < 0) continue;

    const enumBody = text.slice(openIndex + 1, closeIndex);

    const getClassPattern = /\bgetClass\s*\(\s*\)/gu;
    for (const call of findAllMatches(enumBody, getClassPattern)) {
      const absoluteStart = openIndex + 1 + call.startOffset;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteStart + call.matchedText.length,
          text: call.matchedText,
        }),
      );
    }
  }

  return findings;
}

function collectDeprecatedThreadMethodsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.deprecatedThreadMethods;
  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\.\s*(?:stop|suspend|resume)\s*\(/gu,
  });
}

function collectPossibleNullAccessFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.possibleNullAccess,
    appliesTo: 'block',
    pattern:
      /\b\w+\.\s*(?:get|poll|peek|element|remove)\s*\([^)]*\)\s*\.\s*\w+\s*\(/gu,
  });
}

function collectPossibleNullAccessExceptionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.possibleNullAccessException,
    appliesTo: 'block',
    pattern:
      /\.\s*available\s*\(/gu,
    predicate: (match) => {
      const before = match.matchedText.slice(0, match.startOffset);
      const prefix = text.slice(Math.max(0, match.startOffset - 120), match.startOffset);
      return /\b(?:catch|finally)\b/.test(prefix);
    },
  });
}

function collectInvalidatedIteratorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.invalidatedIterator;
  const findings: ObservedFact[] = [];

  const forEachPattern = /\bfor\s*\([^;]*\s*:\s*(\w+)\s*\)\s*\{/gu;
  for (const match of text.matchAll(forEachPattern)) {
    const collectionName = match[1];
    const openIndex = (match.index ?? 0) + match[0].length - 1;
    const closeIndex = findMatchingDelimiter(text, openIndex, '{', '}');
    if (closeIndex < 0) continue;

    const bodyText = text.slice(openIndex + 1, closeIndex);
    const modifyPattern = new RegExp(
      `\\b${escapeRegex(collectionName)}\\.\\s*(?:add|remove|put|clear|addAll|removeAll|retainAll)\\s*\\(`,
      'gu',
    );
    if (modifyPattern.test(bodyText)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.index ?? 0,
          endOffset: closeIndex + 1,
          text: match[0],
        }),
      );
    }
  }

  return findings;
}

function collectMutableDataExposedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.mutableDataExposed;
  const findings: ObservedFact[] = [];

  // Step 1: collect mutable non-final fields (List, Set, Map, array, StringBuilder, etc.)
  const mutableFields = new Map<string, string>();
  const fieldDeclPattern =
    /(?:private|protected)\s+(?:(?:static|final)\s+)*(\w+(?:<[^>]*>)?(?:\[\])*)\s+(\w+)\s*;/gu;
  for (const decl of text.matchAll(fieldDeclPattern)) {
    const type = decl[1];
    const name = decl[2];
    const isFinal = decl[0].includes('final');
    if (isFinal) continue;
    const isMutable =
      /\b(?:List|Set|Map|Queue|Deque|Collection|StringBuilder|StringBuffer|String\[\]|int\[\]|byte\[\]|Object\[\]|char\[\]|long\[\]|double\[\]|float\[\]|short\[\]|boolean\[\])\b/.test(
        type,
      );
    if (isMutable) {
      mutableFields.set(name, type);
    }
  }

  if (mutableFields.size === 0) return findings;

  // Step 2: find constructor declarations with their parameter names
  const constructorPattern =
    /(?:public|protected|private)?\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;
  for (const ctor of text.matchAll(constructorPattern)) {
    const ctorName = ctor[1];
    const params = ctor[2];

    // Find constructor body
    const ctorOpen = (ctor.index ?? 0) + ctor[0].length - 1;
    const ctorClose = findMatchingDelimiter(
      text,
      ctorOpen,
      '{',
      '}',
    );
    if (ctorClose < 0) continue;

    const ctorBody = text.slice(ctorOpen + 1, ctorClose);

    // Collect parameter names with mutable types
    const paramPattern = /(\w+(?:<[^>]*>)?(?:\[\])*)\s+(\w+)(?:\s*,\s*|$)/gu;
    for (const param of params.matchAll(paramPattern)) {
      const paramType = param[1];
      const paramName = param[2];

      const isMutableParam =
        /\b(?:List|Set|Map|Queue|Deque|Collection|StringBuilder|StringBuffer|String\[\]|int\[\]|byte\[\]|Object\[\])\b/.test(
          paramType,
        );
      if (!isMutableParam) continue;

      // Look for this.field = paramName or field = paramName in constructor body
      const assignPattern = new RegExp(
        `(?:this\\.)?${escapeRegex(paramName)}\\s*=\\s*${escapeRegex(paramName)}\\s*;`,
        'g',
      );
      for (const assign of ctorBody.matchAll(assignPattern)) {
        const assignText = assign[0];
        const absoluteStart = ctorOpen + 1 + (assign.index ?? 0);

        // Check if there's a defensive copy nearby
        const beforeAssign = ctorBody.slice(
          Math.max(0, (assign.index ?? 0) - 120),
          assign.index ?? 0,
        );
        if (
          /new\s+(?:ArrayList|HashSet|HashMap|LinkedList|TreeSet|TreeMap|ArrayDeque|PriorityQueue|ConcurrentHashMap|CopyOnWriteArrayList)\s*[<(]/.test(
            beforeAssign,
          ) ||
          /Collections\.(?:unmodifiable|synchronized)/.test(beforeAssign) ||
          /\.clone\s*\(/.test(beforeAssign) ||
          /Arrays\.copyOf/.test(beforeAssign) ||
          new RegExp(
            `\\b${escapeRegex(paramName)}\\.stream\\b`,
          ).test(beforeAssign)
        ) {
          continue;
        }

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteStart + assignText.length,
            text: assignText,
          }),
        );
      }
    }
  }

  return findings;
}

function collectDurationWithNanosMisuseFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.durationWithNanosMisuse,
    appliesTo: 'block',
    pattern: /\.\s*withNanos\s*\(/gu,
  });
}

function collectIndexOfReversedArgumentsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.indexOfReversedArguments,
    appliesTo: 'block',
    pattern: /\.\s*indexOf\s*\(\s*(\d+)\s*,\s*"/gu,
  });
}

function collectNCopiesArgumentOrderFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.nCopiesArgumentOrder,
    appliesTo: 'block',
    pattern: /\bCollections\.nCopies\s*\(\s*"[^"]*"\s*,/gu,
  });
}

function collectClassIsInstanceOnClassFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.classIsInstanceOnClass,
    appliesTo: 'block',
    pattern: /\.class\s*\.\s*isInstance\s*\(/gu,
  });
}

// --- Batch 15 (JAVA-E) collectors ---

function collectZoneIdInvalidTimezoneFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.zoneIdInvalidTimezone,
    appliesTo: 'block',
    pattern: /\bZoneId\.of\s*\(\s*"[^"]*"\s*\)/gu,
  });
}

function collectTimezoneInvalidIdFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.timezoneInvalidId,
    appliesTo: 'block',
    pattern: /\bTimeZone\.getTimeZone\s*\(\s*"[^"]*"\s*\)/gu,
  });
}

function collectInstantUnsupportedTemporalUnitFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.instantUnsupportedTemporalUnit;
  const findings: ObservedFact[] = [];

  const patterns: RegExp[] = [
    /\.\s*(?:plus|minus|until)\s*\([^,]*,\s*ChronoUnit\.(?:WEEKS|MONTHS|YEARS|DECADES|CENTURIES|MILLENNIA|ERAS|FOREVER)\b/gu,
    /\.\s*get(?:Long)?\s*\(\s*ChronoField\.(?!INSTANT_SECONDS|NANO_OF_SECOND|MICRO_OF_SECOND|MILLI_OF_SECOND)\w+/gu,
  ];

  for (const pattern of patterns) {
    for (const match of findAllMatches(text, pattern)) {
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

function collectIterablePathTypeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.iterablePathType,
    appliesTo: 'block',
    pattern: /\bIterable\s*<\s*(?:java\.nio\.file\.)?Path\s*>/gu,
  });
}

function collectThrowNullFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.throwNull,
    appliesTo: 'block',
    pattern: /\bthrow\s+null\s*;/gu,
  });
}

function collectHashtableContainsValueFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.hashtableContainsValue;
  const findings: ObservedFact[] = [];

  const mapTypePattern = /\b(Hashtable|ConcurrentHashMap)\b[\s\S]{0,200}\.\s*contains\s*\(/gu;

  for (const match of findAllMatches(text, mapTypePattern)) {
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

function collectSystemExitFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.systemExit,
    appliesTo: 'block',
    pattern: /\bSystem\.exit\s*\(/gu,
  });
}

// --- Batch 22 (JAVA-E) collectors ---

function collectUnterminatedAssertChainFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.unterminatedAssertChain,
    appliesTo: 'block',
    pattern: /\.?\b(?:assertThat|verify)\s*\([^)]*\)\s*;/gu,
  });
}

// --- Batch 24 (JAVA-S) collectors ---

export function collectPreparedStatementInLoopFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const psPattern = /\b(?:connection|conn|con)\.(?:prepareStatement|prepareCall)\s*\(/gui;
  const loopPattern = /\b(?:for|while|do)\s*\(/g;

  const psMatches: Array<{ startOffset: number; endOffset: number; text: string }> = [];
  for (const match of text.matchAll(psPattern)) {
    psMatches.push({
      startOffset: match.index!,
      endOffset: match.index! + match[0].length,
      text: match[0],
    });
  }

  if (psMatches.length === 0) return [];

  const lineOffsets = computeLineOffsets(text);
  for (const ps of psMatches) {
    const psLine = offsetToLine(ps.startOffset, lineOffsets);
    loopPattern.lastIndex = 0;
    let foundLoop = false;
    for (const loopMatch of text.matchAll(loopPattern)) {
      const loopLine = offsetToLine(loopMatch.index!, lineOffsets);
      const loopBlockStart = text.indexOf('{', loopMatch.index!);
      if (loopBlockStart < 0) continue;
      const loopBlockEnd = findMatchingDelimiter(text, loopBlockStart, '{', '}');
      if (loopBlockEnd < 0) continue;
      if (ps.startOffset >= loopBlockStart && ps.startOffset <= loopBlockEnd) {
        foundLoop = true;
        break;
      }
      if (loopLine < psLine && psLine - loopLine <= 20 && ps.startOffset > loopBlockEnd) {
        const lineStart = lineOffsets[psLine];
        const lineEnd = text.indexOf('\n', lineStart) >= 0 ? text.indexOf('\n', lineStart) : text.length;
        const psLineText = text.slice(lineStart, lineEnd);
        if (/\b(?:prepareStatement|prepareCall)\s*\(/i.test(psLineText)) {
          const afterLoop = text.slice(loopBlockEnd + 1, ps.startOffset).trim();
          if (afterLoop.length > 0 && !/^\s*$/.test(afterLoop)) {
            const indent = text.slice(lineOffsets[loopLine], loopMatch.index!);
            if (!indent.startsWith(' ')) continue;
          }
        }
      }
    }
    if (foundLoop) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind: JAVA_CORRECTNESS_FACT_KINDS.preparedStatementInLoop,
          startOffset: ps.startOffset,
          endOffset: ps.endOffset,
          text: ps.text,
        }),
      );
    }
  }

  return findings;
}

export function collectAssertionInProductionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.assertionInProduction,
    appliesTo: 'block',
    pattern: /\bassert\b(?!\s*[A-Z][a-z])/gu,
    predicate: (match) => {
      const ctx = text.slice(match.startOffset, Math.min(text.length, match.endOffset + 60));
      if (/\bassert(?:That|Equals|True|False|Null|NotNull|Same|Array|Throws|DoesNotThrow|Fail)\b/.test(ctx)) {
        return false;
      }
      const afterMatch = text.slice(match.endOffset).match(/^\s*(\S+)/);
      if (afterMatch && /^(?:That|Equals|True|False|Null|NotNull|Same|Array|Throws|DoesNotThrow|Fail)[(.]/.test(afterMatch[1])) {
        return false;
      }
      return true;
    },
  });
}

export function collectArrayComparedToNonArrayFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const arrayNames = collectArrayVariableNames(text);
  if (arrayNames.size === 0) return [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.arrayComparedToNonArray;
  const findings: ObservedFact[] = [];

  for (const name of arrayNames) {
    const eqPattern = new RegExp(
      `(?<![A-Za-z_$0-9.])${escapeRegex(name)}\\s*(?:==|!=)\\s*(?:"[^"]*"|'[^']*'|\\d+(?:\\.\\d+)?(?:[fFLl]|\\b)|true|false|null)`,
      'gu',
    );
    for (const match of text.matchAll(eqPattern)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.index!,
          endOffset: match.index! + match[0].length,
          text: match[0],
        }),
      );
    }

    const equalsPattern = new RegExp(
      `(?<![A-Za-z_$0-9.])${escapeRegex(name)}\\.equals\\s*\\(\\s*(?:"[^"]*"|'[^']*'|\\d+(?:\\.\\d+)?(?:[fFLl]|\\b)|true|false|null)\\s*\\)`,
      'gu',
    );
    for (const match of text.matchAll(equalsPattern)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.index!,
          endOffset: match.index! + match[0].length,
          text: match[0],
        }),
      );
    }
  }

  return findings;
}

export function collectParameterReassignmentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.parameterReassignment;

  const methodParams = new Map<string, Set<string>>();
  const methodPattern =
    /(?:(?:public|protected|private|static|final|abstract|synchronized)\s+)*(?:\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;

  for (const m of text.matchAll(methodPattern)) {
    const methodName = m[1];
    const params = m[2].split(',').map((p) => p.trim()).filter(Boolean);
    const paramNames = new Set<string>();
    let blockStart = m.index! + m[0].length - 1;
    const openBrace = text.indexOf('{', m.index!);
    if (openBrace >= 0) blockStart = openBrace;
    const blockEnd = findMatchingDelimiter(text, blockStart, '{', '}');
    if (blockEnd < 0) continue;

    for (const param of params) {
      const parts = param.split(/\s+/);
      const name = parts[parts.length - 1]?.replace(/\[.*\]/, '').replace(/\.\.\./, '');
      if (name && /^[a-z_$][a-zA-Z0-9_$]*$/.test(name) && !/^(?:int|long|double|float|boolean|char|byte|short|void|String|Object)$/.test(name)) {
        paramNames.add(name);
      }
    }

    if (paramNames.size === 0) continue;

    for (const name of paramNames) {
      const assignPattern = new RegExp(
        `(?<![A-Za-z_$0-9.])${escapeRegex(name)}\\s*=(?!=)`,
        'gu',
      );
      for (const match of text.matchAll(assignPattern)) {
        if (match.index! < blockStart || match.index! > blockEnd) continue;
        const before = text.slice(Math.max(0, match.index! - 40), match.index!);
        if (/\bthis\.\s*$/.test(before)) continue;
        if (/\b(?:for|while|catch)\s*\([^)]*$/.test(before)) continue;
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: match.index!,
            endOffset: match.index! + match[0].length,
            text: match[0],
          }),
        );
      }
    }
  }

  return findings;
}

function findEnclosingMethod(text: string, offset: number): string | null {
  const beforeOffset = text.slice(0, offset);
  const methodPattern =
    /(?:(?:public|protected|private|static|final|abstract|synchronized|native)\s+)*(\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*\(/gu;
  let lastMatch: RegExpExecArray | null = null;
  let match: RegExpExecArray | null;

  while ((match = methodPattern.exec(beforeOffset)) !== null) {
    const braceAfter = beforeOffset.indexOf('{', match.index);
    if (braceAfter >= 0 && braceAfter < offset) {
      const closeIndex = findMatchingDelimiter(
        text,
        braceAfter,
        '{',
        '}',
      );
      if (closeIndex >= offset) {
        lastMatch = match;
        match = methodPattern.exec(beforeOffset);
        continue;
      }
    }
    lastMatch = match;
  }

  return lastMatch ? lastMatch[2] : null;
}

function collectArrayVariableNames(text: string): Set<string> {
  const names = new Set<string>();

  const declarationPattern =
    /\b(?:[A-Za-z_$][A-Za-z0-9_$.]*(?:<[^<>;\n]+>)?)(?:\s*\[\s*\])+\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/gu;

  for (const match of text.matchAll(declarationPattern)) {
    names.add(match[1]);
  }

  return names;
}

function collectOptionalVariableNames(text: string): Set<string> {
  const names = new Set<string>();

  const typedPattern =
    /\b(?:Optional|OptionalInt|OptionalLong|OptionalDouble)(?:<[^<>;\n]+>)?\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/gu;
  for (const match of text.matchAll(typedPattern)) {
    names.add(match[1]);
  }

  const assignmentPattern =
    /\b(?:var\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*Optional\.(?:of|ofNullable|empty)\s*\(/gu;
  for (const match of text.matchAll(assignmentPattern)) {
    names.add(match[1]);
  }

  return names;
}

function computeLineOffsets(text: string): number[] {
  const offsets: number[] = [0];

  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === '\n') {
      offsets.push(index + 1);
    }
  }

  return offsets;
}

function offsetToLine(offset: number, lineOffsets: number[]): number {
  let low = 0;
  let high = lineOffsets.length - 1;

  while (low <= high) {
    const mid = (low + high) >>> 1;
    const start = lineOffsets[mid];

    if (start === offset) {
      return mid;
    }

    if (start < offset) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  return Math.max(0, low - 1);
}

function collectStreamVariableNames(text: string): Set<string> {
  const names = new Set<string>();

  const typedPattern =
    /\b(?:Stream|IntStream|LongStream|DoubleStream)(?:<[^<>;\n]+>)?\s+([A-Za-z_$][A-Za-z0-9_$]*)\b/gu;
  for (const match of text.matchAll(typedPattern)) {
    names.add(match[1]);
  }

  const streamChainPattern =
    /\b([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:\w+\s*\.\s*)?(?:stream|of|iterate|generate|concat)\s*\(/gu;
  for (const match of text.matchAll(streamChainPattern)) {
    const preceding = text.slice(Math.max(0, match.index! - 60), match.index!);
    if (/\b(?:Stream|IntStream|LongStream|DoubleStream)\s/.test(preceding)) {
      names.add(match[1]);
    }
  }

  return names;
}

function isOptionalTyped(text: string, varName: string): boolean {
  const typedPattern = new RegExp(
    `\\bOptional(?:<[^<>;\\n]+>)?\\s+${escapeRegex(varName)}\\b`,
    'gu',
  );
  return typedPattern.test(text);
}

function collectOptionalReturnTypeMethods(text: string): Set<string> {
  const names = new Set<string>();

  const methodPattern =
    /\bOptional(?:<[^<>;\\n]+>)?\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;
  for (const match of text.matchAll(methodPattern)) {
    names.add(match[1]);
  }

  return names;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

/**
 * Replace nested block contents (lambdas, anonymous classes, local classes)
 * with spaces so that control-flow keywords inside them do not count toward the
 * enclosing finally block. Brace counts are preserved at depth > 0 to avoid
 * altering offsets.
 */
function stripNestedBlocks(source: string): string {
  let depth = 0;
  const chars: string[] = source.split('');

  for (let index = 0; index < chars.length; index += 1) {
    const char = chars[index];

    if (char === '{') {
      if (depth > 0) {
        chars[index] = ' ';
      }
      depth += 1;
      continue;
    }

    if (char === '}') {
      depth -= 1;
      if (depth > 0) {
        chars[index] = ' ';
      }
      continue;
    }

    if (depth > 1) {
      chars[index] = char === '\n' ? '\n' : ' ';
    }
  }

  return chars.join('');
}
