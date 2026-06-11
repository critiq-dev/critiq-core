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

  // Batch 06 (JAVA-E) — bug risk / framework correctness facts
  volatileArrayElements: 'java.correctness.volatile-array-elements',
  volatileIncrementNonAtomic: 'java.correctness.volatile-increment-non-atomic',
  unsafeGetresource: 'java.correctness.unsafe-getresource',
  duplicateBinaryArgument: 'java.correctness.duplicate-binary-argument',
  illegalMonitorStateCaught: 'java.correctness.illegal-monitor-state-caught',
  cloneWithoutSuper: 'java.correctness.clone-without-super',
  equalsNull: 'java.correctness.equals-null',

  // Batch 07 (JAVA-E) — bug risk / framework correctness facts
  nonFinalImmutableFields: 'java.correctness.non-final-immutable-fields',
  runfinalizersOnExit: 'java.correctness.runfinalizers-on-exit',
  waitOnCondition: 'java.correctness.wait-on-condition',
  mathMaxMinSwapped: 'java.correctness.math-max-min-swapped',
  explicitFinalizerInvocation: 'java.correctness.explicit-finalizer-invocation',
  enumEqualsMethod: 'java.correctness.enum-equals-method',
  overloadedEquals: 'java.correctness.overloaded-equals',

  // Batch 08 (JAVA-E) — bug risk / framework correctness facts
  equalsInheritsParent: 'java.correctness.equals-inherits-parent',
  equalsNullCheck: 'java.correctness.equals-null-check',
  comparetoMinValue: 'java.correctness.compareto-min-value',
  servletMutableFields: 'java.correctness.servlet-mutable-fields',
  runnableRunDirect: 'java.correctness.runnable-run-direct',
  twoLockWait: 'java.correctness.two-lock-wait',
  syncBoxedPrimitive: 'java.correctness.sync-boxed-primitive',
  classNameCollision: 'java.correctness.class-name-collision',

  // Batch 09 (JAVA-E) — bug risk / framework correctness facts
  ignoredInputstreamRead: 'java.correctness.ignored-inputstream-read',
  ignoredInputstreamSkip: 'java.correctness.ignored-inputstream-skip',
  constructorStartsThread: 'java.correctness.constructor-starts-thread',
  forLoopMismatchedIncrement: 'java.correctness.for-loop-mismatched-increment',
  readlineWithoutNullCheck: 'java.correctness.readline-without-null-check',
  unsynchronizedWaitNotify: 'java.correctness.unsynchronized-wait-notify',
  selfAssignment: 'java.correctness.self-assignment',
  syncOnLockPrimitive: 'java.correctness.sync-on-lock-primitive',

  // Batch 10 (JAVA-E) — bug risk / framework correctness facts
  resultSetIndexZero: 'java.correctness.result-set-index-zero',
  preparedStatementIndexZero: 'java.correctness.prepared-statement-index-zero',
  impossibleToArrayDowncast: 'java.correctness.impossible-toarray-downcast',
  invalidRegexLiteral: 'java.correctness.invalid-regex-literal',
  lostIncrementInAssignment: 'java.correctness.lost-increment-in-assignment',
  // Batch 11 (JAVA-E) — bug risk / framework facts
  shiftOutOfRange: 'java.correctness.shift-out-of-range',
  oddnessCheckFailsNegative: 'java.correctness.oddness-check-fails-negative',
  hasNextInvokesNext: 'java.correctness.hasnext-invokes-next',
  threadSleepWithLock: 'java.correctness.thread-sleep-with-lock',
  stringFormatArgMismatch: 'java.correctness.string-format-arg-mismatch',
  badShortCircuitNullCheck: 'java.correctness.bad-short-circuit-null-check',
  waitNotifyOnThread: 'java.correctness.wait-notify-on-thread',

  // Batch 12 (JAVA-E) — bug risk / framework facts
  switchStatementLabels: 'java.correctness.switch-statement-labels',
  weekYearInDatePattern: 'java.correctness.week-year-in-date-pattern',
  jumpInFinally: 'java.correctness.jump-in-finally',
  defaultPackageSpringScan: 'java.correctness.default-package-spring-scan',
  caseInsensitiveRegexLacksUnicode: 'java.correctness.case-insensitive-regex-lacks-unicode',
  assertSelfComparison: 'java.correctness.assert-self-comparison',
  optionalGetWithoutPresentCheck: 'java.correctness.optional-get-without-present-check',
  iterableIteratorReturnsThis: 'java.correctness.iterable-iterator-returns-this',

  // Batch 13 (JAVA-E) — bug risk / framework correctness facts
  randomCoercedToZero: 'java.correctness.random-coerced-to-zero',
  mutableEnumFields: 'java.correctness.mutable-enum-fields',
  noAllocationMethodCreatesObject: 'java.correctness.noallocation-method-creates-object',

  // Batch 14 (JAVA-E) — bug risk / framework correctness facts
  collectionContainsSelf: 'java.correctness.collection-contains-self',
  collectionAddsSelf: 'java.correctness.collection-adds-self',
  modulusMultiplicationPrecedence: 'java.correctness.modulus-multiplication-precedence',
  bitwiseOrNeverEqual: 'java.correctness.bitwise-or-never-equal',
  getterSetterSyncMismatch: 'java.correctness.getter-setter-sync-mismatch',

  // Batch 15 (NEW) — JAVA-E1082, E1095, E1103, E1108
  threadGroupDeprecatedMethods: 'java.correctness.threadgroup-deprecated-methods',
  closeableProvidesInjection: 'java.correctness.closeable-provides-injection',
  nonNullMethodReturnsNull: 'java.correctness.non-null-method-returns-null',
  missingEnumSwitchElements: 'java.correctness.missing-enum-switch-elements',
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

    // Batch 06 (JAVA-E) — bug risk / framework facts
    ...collectVolatileArrayElementsFacts(text, detector),
    ...collectVolatileIncrementNonAtomicFacts(text, detector),
    ...collectUnsafeGetresourceFacts(text, detector),
    ...collectDuplicateBinaryArgumentFacts(text, detector),
    ...collectIllegalMonitorStateCaughtFacts(text, detector),
    ...collectCloneWithoutSuperFacts(text, detector),
    ...collectEqualsNullFacts(text, detector),

    // Batch 07 (JAVA-E) — bug risk / framework facts
    ...collectNonFinalImmutableFieldsFacts(text, detector),
    ...collectRunfinalizersOnExitFacts(text, detector),
    ...collectWaitOnConditionFacts(text, detector),
    ...collectMathMaxMinSwappedFacts(text, detector),
    ...collectExplicitFinalizerInvocationFacts(text, detector),
    ...collectEnumEqualsMethodFacts(text, detector),
    ...collectOverloadedEqualsFacts(text, detector),

    // Batch 08 (JAVA-E) — bug risk / framework facts
    ...collectEqualsInheritsParentFacts(text, detector),
    ...collectEqualsNullCheckFacts(text, detector),
    ...collectComparetoMinValueFacts(text, detector),
    ...collectServletMutableFieldsFacts(text, detector),
    ...collectRunnableRunDirectFacts(text, detector),
    ...collectTwoLockWaitFacts(text, detector),
    ...collectSyncBoxedPrimitiveFacts(text, detector),
    ...collectClassNameCollisionFacts(text, detector),

    // Batch 09 (JAVA-E) — bug risk / framework facts
    ...collectIgnoredInputstreamReadFacts(text, detector),
    ...collectIgnoredInputstreamSkipFacts(text, detector),
    ...collectConstructorStartsThreadFacts(text, detector),
    ...collectForLoopMismatchedIncrementFacts(text, detector),
    ...collectReadlineWithoutNullCheckFacts(text, detector),
    ...collectUnsynchronizedWaitNotifyFacts(text, detector),
    ...collectSelfAssignmentFacts(text, detector),
    ...collectSyncOnLockPrimitiveFacts(text, detector),

    // Batch 10 (JAVA-E) — bug risk / framework facts
    ...collectResultSetIndexZeroFacts(text, detector),
    ...collectPreparedStatementIndexZeroFacts(text, detector),
    ...collectImpossibleToArrayDowncastFacts(text, detector),
    ...collectInvalidRegexLiteralFacts(text, detector),
    ...collectLostIncrementInAssignmentFacts(text, detector),
    // Batch 11 (JAVA-E) — bug risk / framework facts
    ...collectShiftOutOfRangeFacts(text, detector),
    ...collectOddnessCheckFailsNegativeFacts(text, detector),
    ...collectHasNextInvokesNextFacts(text, detector),
    ...collectThreadSleepWithLockFacts(text, detector),
    ...collectStringFormatArgMismatchFacts(text, detector),
    ...collectBadShortCircuitNullCheckFacts(text, detector),
    ...collectWaitNotifyOnThreadFacts(text, detector),

    // Batch 12 (JAVA-E) — bug risk / framework facts
    ...collectSwitchStatementLabelsFacts(text, detector),
    ...collectWeekYearInDatePatternFacts(text, detector),
    ...collectJumpInFinallyFacts(text, detector),
    ...collectDefaultPackageSpringScanFacts(text, detector),
    ...collectCaseInsensitiveRegexLacksUnicodeFacts(text, detector),
    ...collectAssertSelfComparisonFacts(text, detector),
    ...collectOptionalGetWithoutPresentCheckFacts(text, detector),
    ...collectIterableIteratorReturnsThisFacts(text, detector),

    // Batch 13 (JAVA-E) — bug risk / framework facts
    ...collectRandomCoercedToZeroFacts(text, detector),
    ...collectMutableEnumFieldsFacts(text, detector),
    ...collectNoAllocationMethodCreatesObjectFacts(text, detector),

    // Batch 14 (JAVA-E) — bug risk / framework facts
    ...collectCollectionContainsSelfFacts(text, detector),
    ...collectCollectionAddsSelfFacts(text, detector),
    ...collectModulusMultiplicationPrecedenceFacts(text, detector),
    ...collectBitwiseOrNeverEqualFacts(text, detector),
    ...collectGetterSetterSyncMismatchFacts(text, detector),

    // Batch 15 (NEW) — JAVA-E1082, E1095, E1103, E1108
    ...collectThreadGroupDeprecatedMethodsFacts(text, detector),
    ...collectCloseableProvidesInjectionFacts(text, detector),
    ...collectNonNullMethodReturnsNullFacts(text, detector),
    ...collectMissingEnumSwitchElementsFacts(text, detector),
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
      `(?:(?<!super)\\.\\s*${escapeRegex(methodName)}\\s*\\(|(?<!\\.)\\b${escapeRegex(methodName)}\\s*\\()`,
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

// --- Batch 06 (JAVA-E) collectors ---

function collectVolatileArrayElementsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.volatileArrayElements,
    appliesTo: 'block',
    pattern:
      /volatile\s+\w+(?:<[^>]+>)?(?:\s*\[\s*\])+\s+\w+/gu,
    predicate: (match) => {
      const after = text.slice(match.endOffset).match(/^\s*/)?.[0] ?? '';
      const nextChar = text[match.endOffset + after.length];
      return nextChar !== '(';
    },
  });
}

function collectVolatileIncrementNonAtomicFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.volatileIncrementNonAtomic;
  const findings: ObservedFact[] = [];

  const volatileFieldPattern =
    /volatile\s+(long|int|short|byte|char)\s+(\w+)\s*[=;]/gu;

  const volatileFields = new Map<string, string>();
  for (const match of text.matchAll(volatileFieldPattern)) {
    const type = match[1];
    const name = match[2];
    const before = text.slice(Math.max(0, match.index! - 60), match.index!);
    if (/\bAtomic(?:Integer|Long)\b/.test(before)) continue;
    volatileFields.set(name, type);
  }

  if (volatileFields.size === 0) return findings;

  const incPattern = /(\w+)\s*(?:\+\+|--|\+=|-=)/gu;
  for (const match of findAllMatches(text, incPattern)) {
    const varName = match.matchedText.match(/(\w+)/)?.[1];
    if (!varName || !volatileFields.has(varName)) continue;
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

function collectUnsafeGetresourceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.unsafeGetresource,
    appliesTo: 'block',
    pattern:
      /(?:getClass\(\)|\w+\.class)\s*\.\s*getResource\s*\(\s*["'][^/]/gu,
  });
}

function collectDuplicateBinaryArgumentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.duplicateBinaryArgument;
  const findings: ObservedFact[] = [];

  const dupPattern =
    /(\w+(?:\.\w+)*)\s*(==|!=)\s*(\w+(?:\.\w+)*)\s*(?:\|\||&&)\s*\1\s*\2\s*\3/gu;

  for (const match of findAllMatches(text, dupPattern)) {
    const matched = match.matchedText;
    if (/\*/.test(matched)) continue;

    const callPattern = /\w+\s*\([^)]*\)\s*(?:\|\||&&)\s*\w+\s*\([^)]*\)/;
    if (callPattern.test(matched)) continue;

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: matched,
        props: { confidence: 0.75 },
      }),
    );
  }

  return findings;
}

function collectIllegalMonitorStateCaughtFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.illegalMonitorStateCaught,
    appliesTo: 'block',
    pattern:
      /\bcatch\s*\([^)]*\bIllegalMonitorStateException\b[^)]*\)/gu,
  });
}

function collectCloneWithoutSuperFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.cloneWithoutSuper;
  const findings: ObservedFact[] = [];

  if (/\bfinal\s+class\b/.test(text)) return findings;

  const cloneMethodPattern =
    /(?:(?:public|protected|private)\s+)?\s*(?:Object\s+)?clone\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;

  for (const match of text.matchAll(cloneMethodPattern)) {
    const openIndex = (match.index ?? 0) + match[0].lastIndexOf('{');
    if (openIndex < 0) continue;

    const closeIndex = findMatchingDelimiter(text, openIndex, '{', '}');
    if (closeIndex < 0) continue;

    const bodyText = text.slice(openIndex + 1, closeIndex);
    if (/\bsuper\s*\.\s*clone\s*\(/.test(bodyText)) continue;

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

  return findings;
}

function collectEqualsNullFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.equalsNull,
    appliesTo: 'block',
    pattern:
      /\w+(?:\.\w+)*\.equals\s*\(\s*null\s*\)/gu,
    predicate: (match) => {
      const lhs = match.matchedText.split('.equals')[0];
      if (!lhs) return false;
      return !/^"[^"]*"$/.test(lhs) && !/^'[^']*'$/.test(lhs);
    },
  });
}

// --- Batch 07 (JAVA-E) collectors ---

function collectNonFinalImmutableFieldsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.nonFinalImmutableFields;
  const findings: ObservedFact[] = [];

  const immutableAnnotationPattern =
    /@(?:javax\.annotation\.concurrent\.Immutable|Immutable|Value|lombok\.Value)\b/gu;

  for (const annMatch of findAllMatches(text, immutableAnnotationPattern)) {
    const afterAnn = text.slice(annMatch.endOffset);
    const classMatch = afterAnn.match(/^\s*(?:public\s+)?(?:abstract\s+)?(?:class|record)\s+\w+/);
    if (!classMatch) continue;

    const classStart = annMatch.endOffset + classMatch.index!;
    const openBrace = text.indexOf('{', classStart);
    if (openBrace < 0) continue;

    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const body = text.slice(openBrace + 1, closeBrace);
    const fieldPattern = /\b(?:private|protected|public)\s+(?:static\s+)?(\w+(?:<[^>]*>)?(?:\s*\[\s*\])?)\s+(\w+)\s*[=;]/gu;
    for (const fieldMatch of body.matchAll(fieldPattern)) {
      if (!/\bfinal\b/.test(fieldMatch[0])) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: openBrace + 1 + (fieldMatch.index ?? 0),
            endOffset: openBrace + 1 + (fieldMatch.index ?? 0) + fieldMatch[0].length,
            text: fieldMatch[0],
          }),
        );
      }
    }
  }

  return findings;
}

function collectRunfinalizersOnExitFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.runfinalizersOnExit,
    appliesTo: 'block',
    pattern:
      /(?:System\.runFinalizersOnExit|Runtime\.getRuntime\(\)\.runFinalizersOnExit)\s*\(/gu,
  });
}

function collectWaitOnConditionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.waitOnCondition;
  const findings: ObservedFact[] = [];
  const conditionVars = new Set<string>();

  const newConditionPattern = /(\w+)\s*=\s*\w+\.newCondition\s*\(/gu;
  for (const match of text.matchAll(newConditionPattern)) {
    conditionVars.add(match[1]);
  }

  if (conditionVars.size === 0) return findings;

  const waitPattern = /(\w+)\.wait\s*\(/gu;
  for (const match of text.matchAll(waitPattern)) {
    const varName = match[1];
    if (conditionVars.has(varName)) {
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

function collectMathMaxMinSwappedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.mathMaxMinSwapped,
    appliesTo: 'block',
    pattern:
      /Math\.(max|min)\s*\(\s*(\w+)\s*,\s*Math\.(min|max)\s*\(\s*\2\s*,/gu,
  });
}

function collectExplicitFinalizerInvocationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.explicitFinalizerInvocation;
  const findings: ObservedFact[] = [];

  const finalizeCallPattern = /\w+\.finalize\s*\(/gu;
  for (const match of findAllMatches(text, finalizeCallPattern)) {
    const beforeCall = text.slice(0, match.startOffset);
    const methodPattern = /\b(?:protected\s+)?void\s+finalize\s*\(\s*\)\s*(?:throws\s+\w+)?\s*\{/gu;
    let insideFinalizeMethod = false;
    let m: RegExpExecArray | null;
    while ((m = methodPattern.exec(beforeCall)) !== null) {
      const openBrace = beforeCall.indexOf('{', m.index);
      if (openBrace < 0) continue;
      const closeBrace = findMatchingDelimiter(beforeCall, openBrace, '{', '}');
      if (closeBrace === -1 || closeBrace >= match.startOffset) {
        insideFinalizeMethod = true;
        break;
      }
    }
    if (!insideFinalizeMethod) {
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

function collectEnumEqualsMethodFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.enumEqualsMethod;
  const findings: ObservedFact[] = [];

  const enumPattern = /\benum\s+(\w+)\s*\{/gu;
  for (const enumMatch of text.matchAll(enumPattern)) {
    const openBrace = (enumMatch.index ?? 0) + enumMatch[0].indexOf('{');
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const enumBody = text.slice(openBrace + 1, closeBrace);
    const equalsPattern = /\b(?:public\s+)?boolean\s+equals\s*\(/gu;
    if (equalsPattern.test(enumBody)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: openBrace + 1,
          endOffset: closeBrace,
          text: `equals() in enum body`,
        }),
      );
    }
  }

  return findings;
}

function collectOverloadedEqualsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.overloadedEquals;
  const findings: ObservedFact[] = [];

  const equalsPattern = /\b(?:public\s+)?boolean\s+equals\s*\(\s*(\w+(?:\[\])?)(?:\s+\w+)\s*\)/gu;
  for (const match of text.matchAll(equalsPattern)) {
    const paramType = match[1];
    if (paramType !== 'Object') {
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

// --- Batch 08 (JAVA-E) collectors ---

function collectEqualsInheritsParentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.equalsInheritsParent;
  const findings: ObservedFact[] = [];

  const classPattern = /\bclass\s+(\w+)(?:<[^>]+>)?\s+extends\s+(\w+)\s*\{/gu;
  for (const cls of text.matchAll(classPattern)) {
    const openBrace = (cls.index ?? 0) + cls[0].length - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const classBody = text.slice(openBrace + 1, closeBrace);
    const hasObjectEqualsOverride = /\b(@Override\s+)?public\s+boolean\s+equals\s*\(\s*Object\b/.test(classBody);
    if (hasObjectEqualsOverride) continue;

    const overloadedEqualsPattern = /\b(?:public\s+)?boolean\s+equals\s*\(\s*(\w+(?:\[\])?)(?:\s+\w+)\s*\)/gu;
    for (const eqMatch of classBody.matchAll(overloadedEqualsPattern)) {
      const paramType = eqMatch[1];
      if (paramType !== 'Object') {
        const absoluteStart = openBrace + 1 + (eqMatch.index ?? 0);
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteStart + eqMatch[0].length,
            text: eqMatch[0],
          }),
        );
      }
    }
  }

  return findings;
}

function collectEqualsNullCheckFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.equalsNullCheck;
  const findings: ObservedFact[] = [];

  const equalsPattern = /\bboolean\s+equals\s*\(\s*Object\s+(\w+)\s*\)\s*\{/gu;
  for (const match of text.matchAll(equalsPattern)) {
    const paramName = match[1];
    const openBrace = (match.index ?? 0) + match[0].length - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const methodBody = text.slice(openBrace + 1, closeBrace);

    const nullGuardPattern = new RegExp(
      `(?:${escapeRegex(paramName)}\\s*==\\s*null|${escapeRegex(paramName)}\\s*!=\\s*null|this\\s*==\\s*${escapeRegex(paramName)})`,
      'gu',
    );
    if (nullGuardPattern.test(methodBody)) continue;

    const safeCallPattern = new RegExp(
      `Objects\\.equals\\s*\\(\\s*${escapeRegex(paramName)}`,
      'gu',
    );
    if (safeCallPattern.test(methodBody)) continue;

    const derefPattern = new RegExp(
      `${escapeRegex(paramName)}\\.(?!equals\\s*\\()\\w+\\s*\\(`,
      'gu',
    );
    const fieldAccessPattern = new RegExp(
      `${escapeRegex(paramName)}\\.\\w+`,
      'gu',
    );

    const hasDeref = derefPattern.test(methodBody) || fieldAccessPattern.test(methodBody);
    if (hasDeref) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.index ?? 0,
          endOffset: (match.index ?? 0) + match[0].length,
          text: `equals(Object ${paramName}) without null check`,
        }),
      );
    }
  }

  return findings;
}

function collectComparetoMinValueFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.comparetoMinValue;

  const methodPattern = /\b(?:public\s+)?int\s+(compareTo|compare)\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;
  const findings: ObservedFact[] = [];

  for (const match of text.matchAll(methodPattern)) {
    const openBrace = (match.index ?? 0) + match[0].lastIndexOf('{');
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const bodyText = text.slice(openBrace + 1, closeBrace);
    const minValuePattern = /\bInteger\.MIN_VALUE\b|-2147483648/gu;
    for (const valMatch of bodyText.matchAll(minValuePattern)) {
      const absoluteStart = openBrace + 1 + (valMatch.index ?? 0);
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteStart + valMatch[0].length,
          text: valMatch[0],
        }),
      );
    }
  }

  return findings;
}

function collectServletMutableFieldsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.servletMutableFields;
  const findings: ObservedFact[] = [];

  const servletPattern = /\bclass\s+(\w+)\s+extends\s+(?:(?:javax|jakarta)\.servlet\.(?:http\.)?)?(?:HttpServlet|GenericServlet)\b/gu;
  for (const cls of text.matchAll(servletPattern)) {
    const classDeclEnd = (cls.index ?? 0) + cls[0].length;
    const openBrace = text.indexOf('{', classDeclEnd);
    if (openBrace < 0) continue;
    const classClose = findMatchingDelimiter(text, openBrace, '{', '}');
    if (classClose < 0) continue;

    const classBody = text.slice(openBrace + 1, classClose);

    const mutableFields = new Map<string, string>();
    const fieldPattern = /(?:private|protected|public)\s+(?!final\b)(?:(?!static\b)(?:\w+(?:\.\w+)*)(?:<[^>]*>)?(?:\s*\[\s*\])?)\s+(\w+)\s*[=;]/gu;
    for (const f of classBody.matchAll(fieldPattern)) {
      mutableFields.set(f[1], f[1]);
    }

    if (mutableFields.size === 0) continue;

    const handlerPattern = /\b(?:protected|public)\s+(?:void|int|String|boolean|long|Object)\s+(?:doGet|doPost|doPut|doDelete|doHead|doOptions|doTrace|service)\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;
    for (const handler of classBody.matchAll(handlerPattern)) {
      const handlerOpen = (handler.index ?? 0) + handler[0].lastIndexOf('{');
      const handlerClose = findMatchingDelimiter(classBody, handlerOpen, '{', '}');
      if (handlerClose < 0) continue;

      const handlerBody = classBody.slice(handlerOpen + 1, handlerClose);
      const hasSync = /\bsynchronized\s*\(/.test(handlerBody);
      if (hasSync) continue;

      for (const [fieldName] of mutableFields) {
        const accessPattern = new RegExp(
          `(?<![A-Za-z_$0-9.])${escapeRegex(fieldName)}(?![A-Za-z_$0-9])`,
          'gu',
        );
        if (accessPattern.test(handlerBody)) {
          const absoluteStart = openBrace + 1 + handlerOpen + 1;
          const accessMatch = handlerBody.match(accessPattern);
          if (accessMatch) {
            findings.push(
              createOffsetFact(text, {
                detector,
                appliesTo: 'block',
                kind,
                startOffset: absoluteStart + (accessMatch.index ?? 0),
                endOffset: absoluteStart + (accessMatch.index ?? 0) + fieldName.length,
                text: fieldName,
              }),
            );
          }
        }
      }
    }
  }

  return findings;
}

function collectRunnableRunDirectFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.runnableRunDirect,
    appliesTo: 'block',
    pattern: /(\w+(?:\.\w+)*)\.run\s*\(\s*\)/gu,
    predicate: (match) => !/super\.run\s*\(/.test(match.matchedText),
    props: () => ({ confidence: 0.80 }),
  });
}

function collectTwoLockWaitFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.twoLockWait;
  const findings: ObservedFact[] = [];

  const syncPattern = /\bsynchronized\s*\([^)]*\)\s*\{/gu;
  const syncBlocks: Array<{ syncOpen: number; syncClose: number }> = [];

  for (const sync of text.matchAll(syncPattern)) {
    const syncOpen = (sync.index ?? 0) + sync[0].lastIndexOf('{');
    const syncClose = findMatchingDelimiter(text, syncOpen, '{', '}');
    if (syncClose >= 0) {
      syncBlocks.push({ syncOpen, syncClose });
    }
  }

  if (syncBlocks.length < 2) return findings;

  for (let i = 0; i < syncBlocks.length; i++) {
    for (let j = 0; j < syncBlocks.length; j++) {
      if (i === j) continue;
      if (syncBlocks[j].syncOpen > syncBlocks[i].syncOpen && syncBlocks[j].syncClose < syncBlocks[i].syncClose) {
        const innerBody = text.slice(syncBlocks[j].syncOpen + 1, syncBlocks[j].syncClose);
        const waitPattern = /\b(?:this\.)?wait\s*\(\s*\)/gu;
        for (const wait of innerBody.matchAll(waitPattern)) {
          const absoluteStart = syncBlocks[j].syncOpen + 1 + (wait.index ?? 0);
          findings.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: absoluteStart,
              endOffset: absoluteStart + wait[0].length,
              text: wait[0],
            }),
          );
        }
      }
    }
  }

  return findings;
}

function collectSyncBoxedPrimitiveFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.syncBoxedPrimitive;
  const findings: ObservedFact[] = [];

  const boxedTypes = ['Integer', 'Long', 'Short', 'Byte', 'Boolean', 'Character', 'Float', 'Double'];
  const boxedVars = new Set<string>();

  for (const boxedType of boxedTypes) {
    const declPattern = new RegExp(
      `\\b${boxedType}\\s+(\\w+)\\s*[=;]`,
      'gu',
    );
    for (const decl of text.matchAll(declPattern)) {
      boxedVars.add(decl[1]);
    }
  }

  if (boxedVars.size === 0) return findings;

  const syncPattern = /\bsynchronized\s*\(\s*(\w+)\s*\)/gu;
  for (const sync of text.matchAll(syncPattern)) {
    const monitorName = sync[1];
    if (boxedVars.has(monitorName)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: sync.index ?? 0,
          endOffset: (sync.index ?? 0) + sync[0].length,
          text: sync[0],
        }),
      );
    }
  }

  const factorySyncPattern = /\bsynchronized\s*\(\s*(Integer|Long|Short|Byte|Boolean|Character|Float|Double)\./gu;
  for (const sync of text.matchAll(factorySyncPattern)) {
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: sync.index ?? 0,
        endOffset: (sync.index ?? 0) + sync[0].length,
        text: sync[0],
      }),
    );
  }

  return findings;
}

function collectClassNameCollisionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.classNameCollision;
  const findings: ObservedFact[] = [];

  const classPattern = /\b(?:class|interface)\s+(\w+)\s*(?:<[^>]+>)?\s*(?:extends|implements)\s+([\w.,\s<>\n]+?)(?=\{|implements|extends)/gu;
  for (const cls of text.matchAll(classPattern)) {
    const className = cls[1];
    const superTypes = cls[2];

    const typePattern = /([\w.]+)\b/gu;
    for (const type of superTypes.matchAll(typePattern)) {
      const typeName = type[1];
      if (!typeName.includes('.')) continue;
      const simpleName = typeName.split('.').pop() ?? '';
      if (simpleName === className) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: cls.index ?? 0,
            endOffset: (cls.index ?? 0) + cls[0].length,
            text: cls[0],
          }),
        );
        break;
      }
    }
  }

  return findings;
}

// --- Batch 09 (JAVA-E) collectors ---

function collectIgnoredInputstreamReadFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.ignoredInputstreamRead,
    appliesTo: 'block',
    pattern: /(?<!=\s*)(?<!return\s+)\b\w+\.read\s*\(/gu,
  });
}

function collectIgnoredInputstreamSkipFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.ignoredInputstreamSkip,
    appliesTo: 'block',
    pattern: /(?<!=\s*)(?<!return\s+)\b\w+\.skip\s*\(/gu,
  });
}

function collectConstructorStartsThreadFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.constructorStartsThread;
  const findings: ObservedFact[] = [];
  const nonFinalClasses = new Map<string, { openBrace: number; closeBrace: number }>();

  const classPattern = /(?:\bfinal\s+)?(?:public\s+)?(?:abstract\s+)?(?:class|record)\s+(\w+)\s*(?:extends\s+\w+(?:<[^>]*>)?\s*)?(?:implements[^{]*)?\{/gu;
  for (const cls of text.matchAll(classPattern)) {
    if (cls[0].startsWith('final')) continue;
    const openBrace = (cls.index ?? 0) + cls[0].lastIndexOf('{');
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace >= 0) {
      nonFinalClasses.set(cls[1], { openBrace, closeBrace });
    }
  }

  const ctorPattern = /(?:public|protected|private)?\s*(\w+)\s*\([^)]*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;
  for (const ctor of text.matchAll(ctorPattern)) {
    const ctorName = ctor[1];
    const classInfo = nonFinalClasses.get(ctorName);
    if (!classInfo) continue;

    const ctorOpen = (ctor.index ?? 0) + ctor[0].lastIndexOf('{');
    if (ctorOpen < classInfo.openBrace || ctorOpen > classInfo.closeBrace) continue;

    const ctorClose = findMatchingDelimiter(text, ctorOpen, '{', '}');
    if (ctorClose < 0) continue;

    const ctorBody = text.slice(ctorOpen + 1, ctorClose);
    const threadStartPattern = /\.\s*(?:start\s*\(|(?:execute|submit)\s*\(\s*(?:new\s+)?Thread\s*\()/gu;
    for (const start of ctorBody.matchAll(threadStartPattern)) {
      const absoluteStart = ctorOpen + 1 + (start.index ?? 0);
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteStart + start[0].length,
          text: start[0],
        }),
      );
    }
  }

  return findings;
}

function collectForLoopMismatchedIncrementFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.forLoopMismatchedIncrement;
  const findings: ObservedFact[] = [];

  const forPattern = /\bfor\s*\(\s*(?:\w+(?:\s*<[^>]*>)?\s+)?(\w+)\s*=\s*[^;]+;\s*(\w+)\s*(?:<|>|<=|>=|!=)\s*[^;]+;\s*(\w+)(?:\+\+|--|\s*\+=\s*\d+|\s*-=\s*\d+)\s*\)/gu;
  for (const match of text.matchAll(forPattern)) {
    const initVar = match[1];
    const conditionVar = match[2];
    const incrementVar = match[3];
    if (conditionVar !== incrementVar) {
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

function collectReadlineWithoutNullCheckFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.readlineWithoutNullCheck;
  const findings: ObservedFact[] = [];

  const assignPattern = /(\w+)\s*=\s*(\w+)\.\s*readLine\s*\(\s*\)/gu;
  for (const match of findAllMatches(text, assignPattern)) {
    const assignEnd = match.endOffset;
    const afterText = text.slice(assignEnd);
    const lineStart = assignEnd;
    const lines = afterText.split('\n');

    const varName = match.matchedText.match(/(\w+)\s*=\s*/)?.[1] ?? '';

    const readlineInWhilePattern = /while\s*\(\s*(?:\([^)]*\)\s*)?\s*(?:\w+\s*=\s*)?\w+\.\s*readLine\s*\(\s*\)\s*(?:!=\s*null\s*\))?/;
    const beforeText = text.slice(Math.max(0, match.startOffset - 80), match.startOffset);
    if (readlineInWhilePattern.test(beforeText)) continue;

    let hasNullCheck = false;
    let checkCount = 0;
    for (const line of lines) {
      if (checkCount > 5) break;
      checkCount++;
      const nullCheck = new RegExp(
        `${varName}\\s*(?:==|!=)\\s*null`,
        'gu',
      );
      if (nullCheck.test(line)) {
        hasNullCheck = true;
        break;
      }
    }

    if (!hasNullCheck) {
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

function collectUnsynchronizedWaitNotifyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.unsynchronizedWaitNotify;
  const findings: ObservedFact[] = [];

  const syncBlocks: Array<{ syncOpen: number; syncClose: number }> = [];
  const syncPattern = /\bsynchronized\s*\([^)]*\)\s*\{/gu;
  for (const sync of text.matchAll(syncPattern)) {
    const syncOpen = (sync.index ?? 0) + sync[0].lastIndexOf('{');
    const syncClose = findMatchingDelimiter(text, syncOpen, '{', '}');
    if (syncClose >= 0) {
      syncBlocks.push({ syncOpen, syncClose });
    }
  }

  const waitNotifyPattern = /(\w+)\.\s*(?:wait|notify|notifyAll)\s*\(/gu;
  for (const call of text.matchAll(waitNotifyPattern)) {
    const callOffset = call.index ?? 0;
    const isInsideSync = syncBlocks.some(
      (b) => callOffset > b.syncOpen && callOffset < b.syncClose,
    );
    if (!isInsideSync) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: callOffset,
          endOffset: callOffset + call[0].length,
          text: call[0],
        }),
      );
    }
  }

  return findings;
}

function collectSelfAssignmentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.selfAssignment;
  const findings: ObservedFact[] = [];

  const assignPattern = /(\w+)\s*=\s*\1\s*;/gu;
  for (const match of findAllMatches(text, assignPattern)) {
    const expr = match.matchedText;

    if (/this\./.test(expr)) continue;
    if (/\w+\.\w+\s*=/.test(expr)) continue;

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

function collectSyncOnLockPrimitiveFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.syncOnLockPrimitive;
  const findings: ObservedFact[] = [];
  const lockVars = new Set<string>();

  const lockTypes = [
    'ReentrantLock', 'Lock', 'ReentrantReadWriteLock',
    'StampedLock', 'ReadWriteLock',
  ];
  for (const lockType of lockTypes) {
    const declPattern = new RegExp(
      `\\b${lockType}\\s+(\\w+)\\s*[=;]`,
      'gu',
    );
    for (const decl of text.matchAll(declPattern)) {
      lockVars.add(decl[1]);
    }
  }

  if (lockVars.size === 0) return findings;

  const syncPattern = /\bsynchronized\s*\(\s*(\w+)\s*\)/gu;
  for (const sync of text.matchAll(syncPattern)) {
    const monitorName = sync[1];
    if (lockVars.has(monitorName)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: sync.index ?? 0,
          endOffset: (sync.index ?? 0) + sync[0].length,
          text: sync[0],
        }),
      );
    }
  }

  return findings;
}

function collectResultSetIndexZeroFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.resultSetIndexZero;
  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\b(?:resultSet|rs|results?|rset)\s*\.\s*(?:get|update)[A-Za-z]+\s*\(\s*0(?!\s*[L.lxXbBfFdD])\s*[,)]/gu,
  });
}

function collectPreparedStatementIndexZeroFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.preparedStatementIndexZero;
  const setterMethods = [
    'setString', 'setInt', 'setLong', 'setBoolean', 'setDouble', 'setFloat',
    'setBytes', 'setDate', 'setTime', 'setTimestamp', 'setObject', 'setBigDecimal',
    'setNull', 'setArray', 'setBlob', 'setClob', 'setRef', 'setURL',
    'setNString', 'setNCharacterStream', 'setBinaryStream', 'setAsciiStream',
    'setCharacterStream', 'setRowId', 'setSQLXML',
  ].join('|');
  const varNames = 'preparedStatement|pstmt|ps|prepStmt|stmt|statement';
  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: new RegExp(
      `\\b(?:${varNames})\\s*\\.\\s*(?:${setterMethods})\\s*\\(\\s*0\\s*,`,
      'gu',
    ),
  });
}

function collectImpossibleToArrayDowncastFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.impossibleToArrayDowncast;
  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\(\s*\w+(?:\[\]\s*\)|\[\])\s+\w+\s*\.\s*toArray\s*\(\s*\)/gu,
    predicate: (match) => {
      return !/\.\s*toArray\s*\(\s*new\s+\w+\[/u.test(
        text.slice(Math.max(0, match.startOffset - 80), match.endOffset + 20),
      );
    },
  });
}

function collectInvalidRegexLiteralFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.invalidRegexLiteral;
  const findings: ObservedFact[] = [];

  const regexCallPattern =
    /\b(?:Pattern\.compile|Pattern\.matches|String\.matches|String\.replaceAll|String\.replaceFirst|String\.split)\s*\(\s*"((?:[^"\\]|\\.)*)"\s*[,)]/gu;

  const standardEscapes = new Set([
    '\\d', '\\w', '\\s', '\\b', '\\D', '\\W', '\\S', '\\B',
    '\\n', '\\t', '\\r', '\\\\', '\\.', '\\+', '\\*', '\\?',
    '\\|', '\\(', '\\)', '\\[', '\\]', '\\{', '\\}', '\\^',
    '\\$', '\\/', '\\0', '\\x', '\\u',
  ]);

  for (const match of text.matchAll(regexCallPattern)) {
    const regexStr = match[1];
    if (!regexStr) continue;

    let invalid = false;

    const openBrackets = (regexStr.match(/\[/gu) ?? []).length;
    const closeBrackets = (regexStr.match(/\]/gu) ?? []).length;
    if (openBrackets !== closeBrackets) invalid = true;

    const openParens = (regexStr.match(/\(/gu) ?? []).length;
    const closeParens = (regexStr.match(/\)/gu) ?? []).length;
    if (openParens !== closeParens) invalid = true;

    if (/\[[\s]*\]/u.test(regexStr)) invalid = true;

    const rangePattern = /\[[^\]]*([a-zA-Z0-9])\s*-\s*([a-zA-Z0-9])\s*[^\]]*\]/gu;
    let rangeMatch: RegExpExecArray | null;
    while ((rangeMatch = rangePattern.exec(regexStr)) !== null) {
      if (rangeMatch[1].charCodeAt(0) > rangeMatch[2].charCodeAt(0)) {
        invalid = true;
        break;
      }
    }

    const escapeSeqPattern = /\\(.)/gu;
    let escMatch: RegExpExecArray | null;
    while ((escMatch = escapeSeqPattern.exec(regexStr)) !== null) {
      const seq = escMatch[0];
      if (!standardEscapes.has(seq)) {
        invalid = true;
        break;
      }
    }

    if (regexStr.endsWith('\\') && !regexStr.endsWith('\\\\')) {
      invalid = true;
    }

    if (invalid) {
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

function collectLostIncrementInAssignmentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.lostIncrementInAssignment;
  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\b(\w+)\s*=\s*\1\s*(\+\+|--)/gu,
    predicate: (match) => {
      const expr = match.matchedText;
      return !/this\./u.test(expr);
    },
  });
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

function collectShiftOutOfRangeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const invalidShiftPattern =
    /[a-zA-Z_]\w*\s*(?:<<|>>>?)\s*(-?\d+)\b/gu;
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.shiftOutOfRange;

  for (const match of text.matchAll(invalidShiftPattern)) {
    const amountStr = match[1];
    const amount = parseInt(amountStr, 10);
    let isInvalid = false;

    if (amount < 0) {
      isInvalid = true;
    } else if (amount >= 64) {
      isInvalid = true;
    }

    if (!isInvalid) {
      continue;
    }

    const startOffset = match.index!;
    const endOffset = startOffset + match[0].length;
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset,
        endOffset,
        text: match[0],
      }),
    );
  }

  return findings;
}

function collectOddnessCheckFailsNegativeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const pattern = /%\s*2[lL]?\s*==\s*1[lL]?/gu;
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.oddnessCheckFailsNegative,
    appliesTo: 'block',
    pattern,
  });
}

function collectHasNextInvokesNextFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.hasNextInvokesNext;

  const hasNextMethodPattern = /\bboolean\s+hasNext\s*\(\s*\)/gu;
  let hasNextPresent = false;
  for (const _ of text.matchAll(hasNextMethodPattern)) {
    hasNextPresent = true;
    break;
  }

  if (!hasNextPresent) {
    return findings;
  }

  const nextCallPattern = /\b\w+(?:\s*\([^)]*\))?\s*\.\s*next\s*\(\s*\)/gu;
  for (const match of text.matchAll(nextCallPattern)) {
    const startOffset = match.index!;
    const endOffset = startOffset + match[0].length;
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset,
        endOffset,
        text: match[0],
      }),
    );
  }

  return findings;
}

function collectThreadSleepWithLockFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.threadSleepWithLock;

  const hasSynchronized = /\bsynchronized\b/u.test(text);
  if (!hasSynchronized) {
    return findings;
  }

  const sleepPattern = /Thread\.sleep\s*\(/gu;
  for (const match of text.matchAll(sleepPattern)) {
    const startOffset = match.index!;
    const endOffset = startOffset + match[0].length;
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset,
        endOffset,
        text: match[0],
      }),
    );
  }

  return findings;
}

function collectStringFormatArgMismatchFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.stringFormatArgMismatch;

  const formatCallPattern =
    /String\.format\s*\(\s*("(?:[^"\\]|\\.)*")\s*((?:,\s*[^,()]+(?:\([^)]*\))?)*)\s*\)/gu;

  for (const match of text.matchAll(formatCallPattern)) {
    const formatStr = match[1];
    const argSection = match[2] || '';

    let specifierCount = 0;
    const specPattern = /%(?:(?:[1-9]\d*)\$)?[sdfFeEgGhHboxXaA%n]/gu;
    for (const specMatch of formatStr.matchAll(specPattern)) {
      const spec = specMatch[0];
      if (spec !== '%%') {
        specifierCount++;
      }
    }

    if (specifierCount === 0) {
      continue;
    }

    const args = argSection
      .split(',')
      .map((a) => a.trim())
      .filter((a) => a.length > 0);
    const argCount = args.length;

    if (specifierCount !== argCount) {
      const startOffset = match.index!;
      const endOffset = startOffset + match[0].length;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset,
          endOffset,
          text: match[0],
        }),
      );
    }
  }

  return findings;
}

function collectBadShortCircuitNullCheckFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const pattern = /(\w+)\s*(?:!=\s*null\s*\|\||==\s*null\s*\|\|)\s*\1\./gu;
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.badShortCircuitNullCheck,
    appliesTo: 'block',
    pattern,
  });
}

function collectWaitNotifyOnThreadFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.waitNotifyOnThread;

  const threadNames = new Set<string>();
  const threadVarPattern =
    /\bThread\s+(thread|[A-Za-z_]\w*thread\w*|t|worker|runner|taskThread)\b/giu;
  for (const match of text.matchAll(threadVarPattern)) {
    threadNames.add(match[1]);
  }

  const waitNotifyPattern =
    /(\w+|\bThread\.currentThread\s*\(\s*\))\s*\.\s*(wait|notify|notifyAll)\s*\(/gu;
  for (const match of text.matchAll(waitNotifyPattern)) {
    const receiver = match[1];
    let isThread = false;

    if (receiver === 'Thread.currentThread()' || receiver === 'Thread.currentThread') {
      isThread = true;
    } else if (threadNames.has(receiver)) {
      isThread = true;
    }

    if (!isThread) {
      continue;
    }

    const startOffset = match.index!;
    const endOffset = startOffset + match[0].length;
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset,
        endOffset,
        text: match[0],
      }),
    );
  }

  return findings;
}

// Batch 12 (JAVA-E) — bug risk / framework collectors

function collectSwitchStatementLabelsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.switchStatementLabels;

  if (!/\bswitch\b/u.test(text)) return findings;

  const switchBlockPattern = /switch\s*\([^)]*\)\s*\{/gu;
  for (const switchMatch of text.matchAll(switchBlockPattern)) {
    const blockStart = (switchMatch.index ?? 0) + switchMatch[0].length - 1;
    let depth = 1;
    let pos = blockStart + 1;

    while (pos < text.length && depth > 0) {
      if (text[pos] === '{') depth++;
      else if (text[pos] === '}') depth--;
      pos++;
    }

    const blockBody = text.slice(blockStart + 1, pos - 1);
    const labelPattern = /^[ \t]*([A-Za-z_]\w*)\s*:/gmu;
    for (const labelMatch of blockBody.matchAll(labelPattern)) {
      const label = labelMatch[1];
      if (label === 'case' || label === 'default') continue;

      const lineStart = blockStart + 1 + (labelMatch.index ?? 0);
      const lineEnd = lineStart + labelMatch[0].length;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: lineStart,
          endOffset: lineEnd,
          text: labelMatch[0].trim(),
        }),
      );
    }
  }

  return findings;
}

function collectWeekYearInDatePatternFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const pattern =
    /(?:SimpleDateFormat|DateTimeFormatter\.ofPattern)\s*\(\s*"((?:[^"\\]|\\.)*)"/gu;
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_CORRECTNESS_FACT_KINDS.weekYearInDatePattern,
    appliesTo: 'block',
    pattern,
    predicate: (match) => {
      const formatStr = match.matchedText;
      const quoteContent = formatStr.match(/"((?:[^"\\]|\\.)*)"/u);
      if (!quoteContent) return false;
      const patternStr = quoteContent[1];
      return /YYYY/u.test(patternStr) && !/\bww\b/u.test(patternStr) && !/\bu\b/u.test(patternStr);
    },
  });
}

function collectJumpInFinallyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.jumpInFinally;

  if (!/\bfinally\b/u.test(text)) return findings;

  const finallyBlockPattern = /finally\s*\{/gu;
  for (const finallyMatch of text.matchAll(finallyBlockPattern)) {
    const blockStart = (finallyMatch.index ?? 0) + finallyMatch[0].length - 1;
    let depth = 1;
    let pos = blockStart + 1;

    while (pos < text.length && depth > 0) {
      if (text[pos] === '{') depth++;
      else if (text[pos] === '}') depth--;
      pos++;
    }

    const blockBody = text.slice(blockStart + 1, pos - 1);
    const stripped = stripNestedBlocks(blockBody);
    const jumpPattern = /\b(?:return|throw)\b[^;]*;/gu;
    for (const jumpMatch of stripped.matchAll(jumpPattern)) {
      const offsetInBlock = jumpMatch.index ?? 0;
      const globalStart = blockStart + 1 + offsetInBlock;
      const globalEnd = globalStart + jumpMatch[0].length;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: globalStart,
          endOffset: globalEnd,
          text: jumpMatch[0].trim(),
        }),
      );
    }
  }

  return findings;
}

function collectDefaultPackageSpringScanFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.defaultPackageSpringScan;
  const findings: ObservedFact[] = [];

  const hasPackageDecl = /\bpackage\s+\w[\w.]*\s*;/u.test(text);
  if (!hasPackageDecl) {
    const annotationPattern =
      /@(?:SpringBootApplication|ComponentScan|ServletComponentScan)\b/gu;
    for (const match of text.matchAll(annotationPattern)) {
      const startOffset = match.index ?? 0;
      const endOffset = startOffset + match[0].length;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset,
          endOffset,
          text: match[0],
        }),
      );
    }
  }

  const emptyScanPattern =
    /@ComponentScan\s*\(\s*(?:basePackages\s*=\s*)?""\s*\)/gu;
  for (const match of text.matchAll(emptyScanPattern)) {
    const startOffset = match.index ?? 0;
    const endOffset = startOffset + match[0].length;
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset,
        endOffset,
        text: match[0],
      }),
    );
  }

  return findings;
}

function collectCaseInsensitiveRegexLacksUnicodeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.caseInsensitiveRegexLacksUnicode;

  const compilePattern =
    /Pattern\.compile\s*\(\s*"[^"]*"\s*,\s*([^)]+)\s*\)/gu;
  for (const match of text.matchAll(compilePattern)) {
    const flags = match[1];
    const hasCaseInsensitive =
      /\bCASE_INSENSITIVE\b/u.test(flags) || /\(\?i\)/u.test(flags);
    const hasUnicode =
      /\bUNICODE_CASE\b/u.test(flags) ||
      /\bUNICODE_CHARACTER_CLASS\b/u.test(flags) ||
      /\(\?u\)/u.test(flags) ||
      /\(\?U\)/u.test(flags);

    if (hasCaseInsensitive && !hasUnicode) {
      const startOffset = match.index ?? 0;
      const endOffset = startOffset + match[0].length;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset,
          endOffset,
          text: match[0],
        }),
      );
    }
  }

  const inlineFlagPattern =
    /["']\(\?\s*i\s*\)["']\s*(?:\.\s*compile\s*\(|(?![^(]*[uU]\)))/gu;
  for (const match of text.matchAll(inlineFlagPattern)) {
    const context = text.slice(
      Math.max(0, (match.index ?? 0) - 60),
      (match.index ?? 0) + match[0].length + 60,
    );
    const hasUnicodeFlag = /\(\?\s*i\s*u\s*\)/u.test(context);
    if (!hasUnicodeFlag) {
      const startOffset = match.index ?? 0;
      const endOffset = startOffset + match[0].length;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset,
          endOffset,
          text: match[0],
        }),
      );
    }
  }

  return findings;
}

function collectAssertSelfComparisonFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.assertSelfComparison;

  const testMethodPattern =
    /\b(?:equals|hashCode|objectMethods)\b/iu;
  if (testMethodPattern.test(text)) {
    const methodNames =
      text.match(/(?:public\s+)?(?:boolean|int)\s+(equals|hashCode)\s*\(/gu) ?? [];
    if (methodNames.length > 0) return findings;
  }

  const assertPattern =
    /\bassert(?:Equals|Same)\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)/gu;
  for (const match of text.matchAll(assertPattern)) {
    if (match[1] === match[2]) {
      const startOffset = match.index ?? 0;
      const endOffset = startOffset + match[0].length;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset,
          endOffset,
          text: match[0],
        }),
      );
    }
  }

  const assertTrueSelfPattern = /assertTrue\s*\(\s*(\w+)\s*==\s*\1\s*\)/gu;
  for (const match of text.matchAll(assertTrueSelfPattern)) {
    const startOffset = match.index ?? 0;
    const endOffset = startOffset + match[0].length;
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset,
        endOffset,
        text: match[0],
      }),
    );
  }

  const hasSameHashCodePattern =
    /(\w+)\s*\.\s*hasSameHashCodeAs\s*\(\s*(\w+)\s*\)/gu;
  for (const match of text.matchAll(hasSameHashCodePattern)) {
    if (match[1] === match[2]) {
      const startOffset = match.index ?? 0;
      const endOffset = startOffset + match[0].length;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset,
          endOffset,
          text: match[0],
        }),
      );
    }
  }

  return findings;
}

function collectOptionalGetWithoutPresentCheckFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.optionalGetWithoutPresentCheck;

  const getCallPattern = /\b(\w+)\s*\.\s*get\s*\(\s*\)/gu;
  const seenReceivers = new Set<string>();

  for (const match of text.matchAll(getCallPattern)) {
    const receiver = match[1];

    if (receiver === 'this' || receiver === 'super') continue;
    if (seenReceivers.has(receiver)) continue;
    seenReceivers.add(receiver);

    const isPresentPattern = new RegExp(
      `\\b${escapeRegex(receiver)}\\s*\\.\\s*isPresent\\s*\\(\\s*\\)`,
      'gu',
    );
    const hasIsPresent = isPresentPattern.test(text);

    if (!hasIsPresent) {
      const startOffset = match.index ?? 0;
      const endOffset = startOffset + match[0].length;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset,
          endOffset,
          text: match[0],
        }),
      );
    }
  }

  return findings;
}

function collectIterableIteratorReturnsThisFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const findings: ObservedFact[] = [];
  const kind = JAVA_CORRECTNESS_FACT_KINDS.iterableIteratorReturnsThis;

  if (!/\bimplements\b[\s\S]*\bIterable\b/i.test(text)) return findings;
  if (!/\bimplements\b[\s\S]*\bIterator\b/i.test(text)) return findings;

  const methodPattern =
    /\bIterator(?:<[^<>;]*>)?\s+\w+\s*\(\s*\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*\{/gu;
  for (const methodMatch of text.matchAll(methodPattern)) {
    const bodyStart = (methodMatch.index ?? 0) + methodMatch[0].length - 1;
    let depth = 1;
    let pos = bodyStart + 1;

    while (pos < text.length && depth > 0) {
      if (text[pos] === '{') depth++;
      else if (text[pos] === '}') depth--;
      pos++;
    }

    const body = text.slice(bodyStart + 1, pos - 1);
    const returnThisPattern = /\breturn\s+this\s*;/gu;
    for (const returnMatch of body.matchAll(returnThisPattern)) {
      const globalStart = bodyStart + 1 + (returnMatch.index ?? 0);
      const globalEnd = globalStart + returnMatch[0].length;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: globalStart,
          endOffset: globalEnd,
          text: returnMatch[0],
        }),
      );
    }
  }

  return findings;
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

// --- Batch 15 (NEW) collectors ---

function collectThreadGroupDeprecatedMethodsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.threadGroupDeprecatedMethods;
  const findings: ObservedFact[] = [];

  const forbiddenMethods =
    /(?:stop|suspend|resume|destroy|isDestroyed|setDaemon|isDaemon|checkAccess|allowThreadSuspension)\s*\(/gu;

  // Static calls: ThreadGroup.stop(...)
  const staticPattern = /\bThreadGroup\s*\.\s*(?:stop|suspend|resume|destroy|isDestroyed|setDaemon|isDaemon|checkAccess|allowThreadSuspension)\s*\(/gu;
  for (const match of findAllMatches(text, staticPattern)) {
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

  // Instance calls: variable.method(...) where method is one of the forbidden methods
  // We match any call to these methods via instance invocation
  const instancePattern = /(\w+(?:\.\w+)*)\s*\.\s*(stop|suspend|resume|destroy|isDestroyed|setDaemon|isDaemon|checkAccess|allowThreadSuspension)\s*\(/gu;
  for (const match of findAllMatches(text, instancePattern)) {
    // Skip if it's a ThreadGroup static call (already handled above) or a Thread method (Batch 13)
    const receiver = match.matchedText.match(/^(\w+(?:\.\w+)*)/)?.[1];
    if (!receiver || receiver === 'ThreadGroup' || receiver.endsWith('.ThreadGroup')) continue;
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

function collectCloseableProvidesInjectionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.closeableProvidesInjection;
  const findings: ObservedFact[] = [];

  const closeableTypes = new Set([
    'FileOutputStream', 'FileInputStream', 'FileReader', 'FileWriter',
    'BufferedReader', 'BufferedWriter', 'BufferedInputStream', 'BufferedOutputStream',
    'PrintWriter', 'PrintStream', 'ObjectOutputStream', 'ObjectInputStream',
    'DataOutputStream', 'DataInputStream',
    'Socket', 'ServerSocket', 'DatagramSocket', 'URLConnection', 'HttpURLConnection',
    'Connection', 'Statement', 'PreparedStatement', 'CallableStatement', 'ResultSet',
    'Scanner', 'Formatter',
  ]);

  // Find @Provides or @Inject annotations on methods (may be same line or previous line)
  const diAnnotationPattern = /@(?:Provides|Inject)\b/gu;

  for (const annMatch of findAllMatches(text, diAnnotationPattern)) {
    const beforeMethod = text.slice(annMatch.startOffset);
    const methodLineMatch = beforeMethod.match(
      /@(?:Provides|Inject)\b[\s\S]{0,200}?\b(?:public|private|protected\s+)?(?:static\s+)?(?:<[^>]+>\s+)?(\w+(?:<[^>]*>)?)\s+\w+\s*\(/u,
    );

    if (!methodLineMatch) continue;

    const returnType = methodLineMatch[1];

    // Check if return type is a known Closeable type
    const baseType = returnType.replace(/<[^>]*>/gu, '');
    if (!closeableTypes.has(baseType)) continue;

    // Check for @SuppressWarnings("CloseableProvides")
    const beforeMethodText = text.slice(
      Math.max(0, annMatch.startOffset - 200),
      annMatch.startOffset,
    );
    if (/@SuppressWarnings\s*\(\s*"CloseableProvides"\s*\)/u.test(beforeMethodText)) continue;

    const absoluteStart = annMatch.startOffset;
    const methodText = methodLineMatch[0];
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: absoluteStart,
        endOffset: absoluteStart + methodText.length,
        text: methodText,
      }),
    );
  }

  return findings;
}

function collectNonNullMethodReturnsNullFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.nonNullMethodReturnsNull;
  const findings: ObservedFact[] = [];

  // Known non-null annotations
  const nonNullAnnotations = [
    'Nonnull', 'NotNull', 'NonNull',
    'javax\\.annotation\\.Nonnull',
    'org\\.jetbrains\\.annotations\\.NotNull',
  ];
  const nonNullPattern = new RegExp(
    `@(?:${nonNullAnnotations.join('|')})\\b`,
    'gu',
  );

  for (const annMatch of findAllMatches(text, nonNullPattern)) {
    // Skip if it's actually a @Nullable annotation that happens to match Nonnull
    const beforeText = text.slice(Math.max(0, annMatch.startOffset - 20), annMatch.startOffset);
    if (/Nullable\s*$/u.test(beforeText)) continue;

    // Find the method declaration following the annotation
    const afterAnn = text.slice(annMatch.startOffset);
    const methodDeclMatch = afterAnn.match(
      /@\w+[\s\S]{0,200}?\b(?:public|private|protected\s+)?(?:static\s+)?(?:final\s+)?(?:<[^>]+>\s+)?(?:\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*\(/u,
    );

    if (!methodDeclMatch) continue;

    const methodDeclEnd = annMatch.startOffset + methodDeclMatch.index! + methodDeclMatch[0].length;

    // Find method body by looking for the opening brace
    const bodyStart = text.indexOf('{', methodDeclEnd);
    if (bodyStart < 0) continue;

    const bodyEnd = findMatchingDelimiter(text, bodyStart, '{', '}');
    if (bodyEnd < 0) continue;

    const methodBody = text.slice(bodyStart + 1, bodyEnd);

    // Find `return null` statements in method body
    const returnNullPattern = /\breturn\s+null\s*;/gu;
    for (const returnMatch of findAllMatches(methodBody, returnNullPattern)) {
      const absoluteStart = bodyStart + 1 + returnMatch.startOffset;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteStart + returnMatch.matchedText.length,
          text: returnMatch.matchedText,
        }),
      );
    }
  }

  return findings;
}

function collectMissingEnumSwitchElementsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.missingEnumSwitchElements;
  const findings: ObservedFact[] = [];

  // Pass 1: Find all enum definitions
  const enumDefs = new Map<string, Set<string>>();
  const enumPattern = /(?:public\s+)?enum\s+(\w+)\s*\{/gu;

  for (const enumMatch of text.matchAll(enumPattern)) {
    const enumName = enumMatch[1];
    const openBrace = (enumMatch.index ?? 0) + enumMatch[0].lastIndexOf('{');
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const enumBody = text.slice(openBrace + 1, closeBrace);
    const members = new Set<string>();

    // Extract enum member names (identifiers before (, ; or , at top level)
    const memberPattern = /(\w+)\s*(?:\(|;|,|\s*$)/gu;
    let memberMatch: RegExpExecArray | null;
    while ((memberMatch = memberPattern.exec(enumBody)) !== null) {
      const name = memberMatch[1];
      // Skip keywords and Java built-in names
      if (/^(?:private|public|protected|static|final|abstract|class|enum|interface|void|int|long|double|float|boolean|char|byte|short)$/u.test(name)) continue;
      // Skip if followed by ( -> likely a method, not an enum constant
      const afterName = enumBody.slice(memberMatch.index! + memberMatch[1].length).trimStart();
      if (afterName.startsWith('(')) continue;
      members.add(name);
    }

    if (members.size > 0) {
      enumDefs.set(enumName, members);
    }
  }

  if (enumDefs.size === 0) return findings;

  // Pass 2: Find switch statements and check for enum coverage
  const switchPattern = /\bswitch\s*\(([^)]+)\)\s*\{/gu;
  for (const switchMatch of text.matchAll(switchPattern)) {
    const switchExpr = switchMatch[1].trim();
    const switchOpen = (switchMatch.index ?? 0) + switchMatch[0].lastIndexOf('{');
    const switchClose = findMatchingDelimiter(text, switchOpen, '{', '}');
    if (switchClose < 0) continue;

    const switchBody = text.slice(switchOpen + 1, switchClose);

    // Check if default is present
    const hasDefault = /\bdefault\s*:/u.test(switchBody);

    // Extract case labels
    const caseLabels = new Set<string>();
    const casePattern = /\bcase\s+(\w+)\s*:/gu;
    let caseMatch: RegExpExecArray | null;
    while ((caseMatch = casePattern.exec(switchBody)) !== null) {
      caseLabels.add(caseMatch[1]);
    }

    // Try to determine the enum type from the switch expression
    let enumType: string | null = null;

    // Check if expression is EnumType.identifier (e.g., Color.RED)
    const qualifiedAccess = switchExpr.match(/^(\w+)\.\w+$/u);
    if (qualifiedAccess) {
      enumType = qualifiedAccess[1];
    }

    // Check if expression is a simple variable — try to find its type from declaration
    if (!enumType && /^\w+$/u.test(switchExpr)) {
      const varPattern = new RegExp(
        `(\\w+(?:<[^>]*>)?)\\s+${switchExpr}\\s*[=;]`,
        'gu',
      );
      const varDecl = varPattern.exec(text);
      if (varDecl) {
        const typeName = varDecl[1].replace(/<[^>]*>/gu, '');
        if (enumDefs.has(typeName)) {
          enumType = typeName;
        }
      }
    }

    // Check method parameter type if it matches an enum
    if (!enumType && /^\w+$/u.test(switchExpr)) {
      const paramPattern = new RegExp(
        `\\([^)]*\\b(\\w+)\\s+${switchExpr}\\b[^)]*\\)`,
        'gu',
      );
      const paramDecl = paramPattern.exec(text);
      if (paramDecl) {
        const typeName = paramDecl[1];
        if (enumDefs.has(typeName)) {
          enumType = typeName;
        }
      }
    }

    if (!enumType) continue;
    if (!enumDefs.has(enumType)) continue;

    const enumMembers = enumDefs.get(enumType)!;
    const missingMembers: string[] = [];

    for (const member of enumMembers) {
      if (!caseLabels.has(member)) {
        missingMembers.push(member);
      }
    }

    if (missingMembers.length > 0 && !hasDefault) {
      const missingText = `Missing: ${missingMembers.join(', ')}`;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: switchMatch.index ?? 0,
          endOffset: switchClose + 1,
          text: missingText,
        }),
      );
    }
  }

  return findings;
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

// --- Batch 13 (JAVA-E) collectors ---

function collectRandomCoercedToZeroFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.randomCoercedToZero;
  const findings: ObservedFact[] = [];

  // (int) Math.random() or (Integer)(Math.random()) without scaling factor
  const castRandomPattern = /\((?:int|Integer)\)\s*\(?\s*Math\.random\s*\(\s*\)\s*\)?/gu;
  for (const match of findAllMatches(text, castRandomPattern)) {
    const afterMatch = text.slice(match.endOffset).match(/^\s*\*\s*\w+/);
    if (afterMatch) continue;
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

  // new Random().nextInt(1) — always returns 0
  const nextIntOnePattern = /\bnew\s+Random\s*\(\s*\)\s*\.\s*nextInt\s*\(\s*1\s*\)/gu;
  for (const match of findAllMatches(text, nextIntOnePattern)) {
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

function collectMutableEnumFieldsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.mutableEnumFields;
  const findings: ObservedFact[] = [];

  const enumPattern = /\benum\s+(\w+)\s*\{/gu;
  for (const enumMatch of text.matchAll(enumPattern)) {
    const openBrace = (enumMatch.index ?? 0) + enumMatch[0].lastIndexOf('{');
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const enumBody = text.slice(openBrace + 1, closeBrace);
    const cleanedBody = stripNestedBlocks(enumBody);

    // Find non-final, non-static field declarations inside enum body
    const fieldPattern = /(?:private|public|protected)\s+(?!final\b)(?!static\b)(\w+(?:\[\])*(?:\s*<[^>]*>)?)\s+(\w+)\s*[=;]/gu;
    for (const field of findAllMatches(cleanedBody, fieldPattern)) {
      const lineStart = cleanedBody.lastIndexOf('\n', field.startOffset) + 1;
      const lineText = cleanedBody.slice(lineStart, cleanedBody.indexOf('\n', field.startOffset) >= 0 ? cleanedBody.indexOf('\n', field.startOffset) : cleanedBody.length);
      if (lineText.includes('(')) continue;

      const absoluteStart = openBrace + 1 + field.startOffset;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteStart + field.matchedText.length,
          text: field.matchedText,
        }),
      );
    }
  }

  return findings;
}

function collectNoAllocationMethodCreatesObjectFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.noAllocationMethodCreatesObject;
  const findings: ObservedFact[] = [];

  // Find @NoAllocation annotation then scan the following method body for `new`
  const noAllocPattern = /@NoAllocation\b([^{]*?(?:\([^)]*\))?)\s*\{/gu;
  for (const match of text.matchAll(noAllocPattern)) {
    const methodOpen = (match.index ?? 0) + match[0].length - 1;
    const methodClose = findMatchingDelimiter(text, methodOpen, '{', '}');
    if (methodClose < 0) continue;

    const methodBody = text.slice(methodOpen + 1, methodClose);
    const cleanedBody = stripNestedBlocks(methodBody);

    // Find `new` keyword creating objects (not array new types)
    const newPattern = /\bnew\s+(?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/gu;
    for (const alloc of findAllMatches(cleanedBody, newPattern)) {
      const absoluteStart = methodOpen + 1 + alloc.startOffset;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteStart + alloc.matchedText.length,
          text: alloc.matchedText,
        }),
      );
    }
  }

  return findings;
}

// --- Batch 14 (JAVA-E) collectors ---

function collectCollectionContainsSelfFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.collectionContainsSelf;
  const findings: ObservedFact[] = [];

  const containsPattern =
    /(?:(\w+)|(this))\s*\.\s*contains\s*\(\s*(?:\1|this)\s*\)/gu;
  for (const match of text.matchAll(containsPattern)) {
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

  const containsValuePattern =
    /(?:(\w+)|(this))\s*\.\s*containsValue\s*\(\s*(?:\1|this)\s*\)/gu;
  for (const match of text.matchAll(containsValuePattern)) {
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

  return findings;
}

function collectCollectionAddsSelfFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.collectionAddsSelf;
  const findings: ObservedFact[] = [];

  const addPattern =
    /(?:(\w+)|(this))\s*\.\s*(?:add|addAll|putAll)\s*\(\s*(?:\1|this)\s*\)/gu;
  for (const match of text.matchAll(addPattern)) {
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

  return findings;
}

function collectModulusMultiplicationPrecedenceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.modulusMultiplicationPrecedence;
  const findings: ObservedFact[] = [];

  const modMultPattern =
    /(\w+(?:\.\w+)?)\s*%\s*(\w+(?:\.\w+)?)\s*\*\s*(\w+(?:\.\w+)?)/gu;
  for (const match of text.matchAll(modMultPattern)) {
    const fullMatch = match[0];
    const matchStart = match.index ?? 0;

    const beforeMatch = text.slice(0, matchStart);
    const precedingChar = beforeMatch.trimEnd().slice(-1);

    if (precedingChar === '(') continue;

    const afterStar = matchStart + fullMatch.indexOf('*') + 1;
    const afterStarTrimmed = text.slice(afterStar).trimStart();
    if (afterStarTrimmed.startsWith(')')) continue;

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: matchStart,
        endOffset: matchStart + fullMatch.length,
        text: fullMatch,
      }),
    );
  }

  return findings;
}

function collectBitwiseOrNeverEqualFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.bitwiseOrNeverEqual;
  const findings: ObservedFact[] = [];

  function parseJavaInteger(raw: string): number | null {
    if (raw.startsWith('0x') || raw.startsWith('0X')) {
      return parseInt(raw.slice(2), 16);
    }
    if (raw.startsWith('0b') || raw.startsWith('0B')) {
      return parseInt(raw.slice(2), 2);
    }
    if (raw.startsWith('0') && raw.length > 1 && /^0[0-7]+$/.test(raw)) {
      return parseInt(raw, 8);
    }
    const num = parseInt(raw, 10);
    if (isNaN(num)) return null;
    return num;
  }

  const orEqualsPattern = /(\w+)\s*\|\s*(\d+)\s*\)?\s*(==|!=)\s*(\d+)/gu;
  for (const match of text.matchAll(orEqualsPattern)) {
    const constB = parseJavaInteger(match[2]);
    const constC = parseJavaInteger(match[4]);
    if (constB === null || constC === null) continue;

    const operator = match[3];

    if (operator === '==') {
      if ((constB & constC) !== constB) {
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
    } else {
      if ((constB & constC) === constB) {
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
  }

  return findings;
}

function collectGetterSetterSyncMismatchFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_CORRECTNESS_FACT_KINDS.getterSetterSyncMismatch;
  const findings: ObservedFact[] = [];

  const classPattern =
    /\b(?:public\s+|protected\s+|private\s+)?(?:abstract\s+|static\s+|final\s+)?(?:class|record)\s+(\w+)\s*(?:extends\s+\w+(?:<[^>]*>)?\s*)?(?:implements[^{]*)?\{/gu;
  for (const cls of text.matchAll(classPattern)) {
    const openBrace = (cls.index ?? 0) + cls[0].lastIndexOf('{');
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const classBody = text.slice(openBrace + 1, closeBrace);

    const getterPattern =
      /\b(synchronized\s+)?(?:public\s+)?(?:static\s+)?\w+\s+(get\w+|is\w+)\s*\(/gu;
    const getters = new Map<
      string,
      { offset: number; synced: boolean }
    >();
    for (const g of classBody.matchAll(getterPattern)) {
      const propName = g[2].startsWith('is')
        ? g[2].slice(2)
        : g[2].slice(3);
      if (!propName) continue;
      const hasSync = !!g[1];
      const methodStart = openBrace + 1 + (g.index ?? 0);
      getters.set(propName.toLowerCase(), {
        offset: methodStart,
        synced: hasSync,
      });
    }

    const setterPattern =
      /\b(synchronized\s+)?(?:public\s+)?(?:static\s+)?void\s+(set\w+)\s*\(/gu;
    const setters = new Map<
      string,
      { offset: number; synced: boolean }
    >();
    for (const s of classBody.matchAll(setterPattern)) {
      const propName = s[2].slice(3);
      if (!propName) continue;
      const hasSync = !!s[1];
      const methodStart = openBrace + 1 + (s.index ?? 0);
      setters.set(propName.toLowerCase(), {
        offset: methodStart,
        synced: hasSync,
      });
    }

    for (const [prop, getterInfo] of getters) {
      const setterInfo = setters.get(prop);
      if (!setterInfo) continue;

      if (getterInfo.synced !== setterInfo.synced) {
        const nonSyncedOffset = getterInfo.synced
          ? setterInfo.offset
          : getterInfo.offset;
        const prefix = getterInfo.synced ? 'set' : 'get';
        const nonSyncedName = `${prefix}${prop.charAt(0).toUpperCase()}${prop.slice(1)}`;
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: nonSyncedOffset,
            endOffset: nonSyncedOffset + nonSyncedName.length + 2,
            text: nonSyncedName,
          }),
        );
      }
    }
  }

  return findings;
}
