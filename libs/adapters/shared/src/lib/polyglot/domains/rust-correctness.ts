import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches, findMatchingDelimiter } from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const RUST_CORRECTNESS_FACT_KINDS = {
  mutexHeldAcrossAwait: 'rust.correctness.mutex-held-across-await',
  threadSleepInAsync: 'rust.correctness.thread-sleep-in-async',
  blockOnInAsync: 'rust.correctness.block-on-in-async',
  forgetJoinHandle: 'rust.correctness.forget-join-handle',
  unboundedChannel: 'rust.correctness.unbounded-channel',
  stdMutexInAsyncFn: 'rust.correctness.std-mutex-in-async-fn',
  uncheckedIndex: 'rust.correctness.unchecked-index',
  syntaxError: 'rust.correctness.syntax-error',
  selfNotSelfType: 'rust.correctness.self-not-self-type',
  invalidRegexLiteral: 'rust.correctness.invalid-regex-literal',
  stepByZero: 'rust.correctness.step-by-zero',
  iterNextInForLoop: 'rust.correctness.iter-next-in-for-loop',
  emptyRangeExpression: 'rust.correctness.empty-range-expression',
  erasingOperation: 'rust.correctness.erasing-operation',
  identicalBinaryOperands: 'rust.correctness.identical-binary-operands',
  mistypedSuffix: 'rust.correctness.mistyped-suffix',
  forgetDropOnReference: 'rust.correctness.forget-drop-on-reference',
  forgetDropOnCopyType: 'rust.correctness.forget-drop-on-copy-type',
  nanComparison: 'rust.correctness.nan-comparison',
  nonOctalPermissions: 'rust.correctness.non-octal-permissions',
  nonBindingLetOnLock: 'rust.correctness.non-binding-let-on-lock',
  unitArgument: 'rust.correctness.unit-argument',
  unitComparison: 'rust.correctness.unit-comparison',
  transmuteIntegerToNonZero: 'rust.correctness.transmute-integer-to-nonzero',
  transmuteIntToFnPtr: 'rust.correctness.transmute-int-to-fn-ptr',
  transmuteIntLitToRawPtr: 'rust.correctness.transmute-int-lit-to-raw-ptr',
  transmuteFloatCharToRefOrPtr: 'rust.correctness.transmute-float-char-to-ref-or-ptr',
  transmuteIntegerToChar: 'rust.correctness.transmute-integer-to-char',
  transmuteNumberToSliceOrArray: 'rust.correctness.transmute-number-to-slice-or-array',
  transmuteTupleToSliceOrArray: 'rust.correctness.transmute-tuple-to-slice-or-array',
  printInDisplayImpl: 'rust.correctness.print-in-display-impl',
  ignoredFutureValue: 'rust.correctness.ignored-future-value',
  hashUnitValue: 'rust.correctness.hash-unit-value',
  transmutePtrToRef: 'rust.correctness.transmute-ptr-to-ref',
  transmuteRefToPtr: 'rust.correctness.transmute-ref-to-ptr',
  transmutePtrToPtr: 'rust.correctness.transmute-ptr-to-ptr',
  forgetDropOnNonDropType: 'rust.correctness.forget-drop-on-non-drop-type',
  unhandledIoResult: 'rust.correctness.unhandled-io-result',
  transmuteTToPtrRef: 'rust.correctness.transmute-t-to-ptr-ref',
  transmuteIntegerToBool: 'rust.correctness.transmute-integer-to-bool',
} as const;

export interface CollectRustCorrectnessFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectRustCorrectnessFacts(
  options: CollectRustCorrectnessFactsOptions,
): ObservedFact[] {
  const { text, detector, path } = options;

  if (path && isRustCorrectnessSuppressedPath(path)) {
    return [];
  }

  return dedupeFacts([
    ...collectMutexHeldAcrossAwaitFacts(text, detector),
    ...collectThreadSleepInAsyncFacts(text, detector),
    ...collectBlockOnInAsyncFacts(text, detector),
    ...collectForgetJoinHandleFacts(text, detector),
    ...collectUnboundedChannelFacts(text, detector),
    ...collectStdMutexInAsyncFnFacts(text, detector),
    ...collectUncheckedIndexFacts(text, detector),
    ...collectSelfNotSelfTypeFacts(text, detector),
    ...collectInvalidRegexLiteralFacts(text, detector),
    ...collectStepByZeroFacts(text, detector),
    ...collectIterNextInForLoopFacts(text, detector),
    ...collectEmptyRangeExpressionFacts(text, detector),
    ...collectErasingOperationFacts(text, detector),
    ...collectIdenticalBinaryOperandsFacts(text, detector),
    ...collectSyntaxErrorFacts(text, detector),
    ...collectMistypedSuffixFacts(text, detector),
    ...collectForgetDropOnReferenceFacts(text, detector),
    ...collectForgetDropOnCopyTypeFacts(text, detector),
    ...collectNaNComparisonFacts(text, detector),
    ...collectNonOctalPermissionsFacts(text, detector),
    ...collectNonBindingLetOnLockFacts(text, detector),
    ...collectUnitArgumentFacts(text, detector),
    ...collectUnitComparisonFacts(text, detector),
    ...collectTransmuteIntegerToNonZeroFacts(text, detector),
    ...collectTransmuteIntToFnPtrFacts(text, detector),
    ...collectTransmuteIntLitToRawPtrFacts(text, detector),
    ...collectTransmuteFloatCharToRefOrPtrFacts(text, detector),
    ...collectTransmuteIntegerToCharFacts(text, detector),
    ...collectTransmuteNumberToSliceOrArrayFacts(text, detector),
    ...collectTransmuteTupleToSliceOrArrayFacts(text, detector),
    ...collectPrintInDisplayImplFacts(text, detector),
    ...collectIgnoredFutureValueFacts(text, detector),
    ...collectHashUnitValueFacts(text, detector),
    ...collectTransmutePtrToRefFacts(text, detector),
    ...collectTransmuteRefToPtrFacts(text, detector),
    ...collectTransmutePtrToPtrFacts(text, detector),
    ...collectForgetDropOnNonDropTypeFacts(text, detector),
    ...collectUnhandledIoResultFacts(text, detector),
    ...collectTransmuteTToPtrRefFacts(text, detector),
    ...collectTransmuteIntegerToBoolFacts(text, detector),
  ]);
}

function isRustCorrectnessSuppressedPath(path: string): boolean {
  return (
    /(^|\/)tests?(\/|$)/u.test(path) ||
    /(^|\/)testdata(\/|$)/u.test(path) ||
    /(^|\/)examples?(\/|$)/u.test(path) ||
    /(^|\/)benches?(\/|$)/u.test(path) ||
    /_test\.rs$/u.test(path) ||
    /\.spec\.rs$/u.test(path)
  );
}

interface AsyncFnBody {
  bodyStart: number;
  bodyEnd: number;
}

/**
 * Flags `std::sync::Mutex` guards from `.lock().unwrap()` or `.lock().expect`
 * that are still referenced after a `.await` in the same `async fn`.
 */
function collectMutexHeldAcrossAwaitFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.mutexHeldAcrossAwait;
  const findings: ObservedFact[] = [];

  for (const body of findAsyncFnBodies(text)) {
    const scope = text.slice(body.bodyStart, body.bodyEnd);
    const lockPattern =
      /\blet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;\n]+\.lock\s*\(\s*\)\s*\.(?:unwrap|expect)\s*\(/gu;

    for (const lockMatch of scope.matchAll(lockPattern)) {
      const guardName = lockMatch[1];
      const lockIndex = lockMatch.index ?? 0;
      const afterLock = scope.slice(lockIndex + lockMatch[0].length);

      const awaitMatch = /\.await\b/u.exec(afterLock);

      if (!awaitMatch || awaitMatch.index === undefined) {
        continue;
      }

      const afterAwait = afterLock.slice(awaitMatch.index + awaitMatch[0].length);
      const guardPattern = new RegExp(
        `(?<![A-Za-z_0-9])${escapeRegex(guardName)}(?![A-Za-z_0-9])`,
        'u',
      );

      if (!guardPattern.test(afterAwait)) {
        continue;
      }

      const absoluteStart = body.bodyStart + lockIndex;
      const absoluteEnd = absoluteStart + lockMatch[0].length;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteEnd,
          text: lockMatch[0],
        }),
      );
    }
  }

  return findings;
}

/** Flags `std::thread::sleep` inside an `async fn` body. */
function collectThreadSleepInAsyncFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectPatternsInAsyncFnBodies({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.threadSleepInAsync,
    pattern: /\bstd::thread::sleep\s*\(/gu,
  });
}

/** Flags blocking executor calls inside an `async fn` body. */
function collectBlockOnInAsyncFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectPatternsInAsyncFnBodies({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.blockOnInAsync,
    pattern:
      /\b(?:Handle::current\(\)\.block_on|Runtime::block_on|futures::executor::block_on)\s*\(/gu,
  });
}

/** Flags `std::mem::forget` applied to a `JoinHandle` or `tokio::spawn` result. */
function collectForgetJoinHandleFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.forgetJoinHandle,
    appliesTo: 'block',
    pattern:
      /\bstd::mem::forget\s*\(\s*(?:tokio::spawn\s*\(|[^)]*\bJoinHandle\b)/gu,
  });
}

/**
 * Flags unbounded MPSC channel constructors. Test and example paths are
 * suppressed at the collector entry point.
 */
function collectUnboundedChannelFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.unboundedChannel,
    appliesTo: 'block',
    pattern:
      /\b(?:tokio::sync::mpsc::unbounded_channel|futures::channel::mpsc::unbounded)\s*\(/gu,
  });
}

/** Flags `std::sync::Mutex<...>` type usage inside an `async fn` body. */
function collectStdMutexInAsyncFnFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectPatternsInAsyncFnBodies({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.stdMutexInAsyncFn,
    pattern: /\bstd::sync::Mutex\s*</gu,
  });
}

/**
 * Flags slice indexing with a simple identifier index (for example `items[i]`)
 * instead of a fallible `.get(i)` access.
 */
function collectUncheckedIndexFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.uncheckedIndex;
  const findings: ObservedFact[] = [];

  const pattern =
    /\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]/gu;

  for (const match of findAllMatches(text, pattern)) {
    const indexName = /\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]/u.exec(
      match.matchedText,
    )?.[1];

    if (!indexName || /^\d+$/u.test(indexName)) {
      continue;
    }

    const before = text.slice(Math.max(0, match.startOffset - 12), match.startOffset);

    if (/\.\s*$/u.test(before)) {
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

/**
 * Flags lowercase `self` used in type position where `Self` is expected.
 * Catches `-> self`, `-> &self`, `fn foo() -> self` patterns.
 */
function collectSelfNotSelfTypeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.selfNotSelfType;
  const findings: ObservedFact[] = [];

  const pattern = /->\s*(?:&'?(?:\w+\s*)?)?self\b/gu;

  for (const match of findAllMatches(text, pattern)) {
    const before = text.slice(Math.max(0, match.startOffset - 40), match.startOffset);

    if (/fn\s+\w+\s*\([^)]*\)\s*->/u.test(before.slice(before.lastIndexOf('\n') + 1))) {
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

/**
 * Flags calls to `Regex::new(...)` or `RegexBuilder::new(...)` with
 * invalid regex patterns (reversed character ranges).
 */
function collectInvalidRegexLiteralFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.invalidRegexLiteral;
  const findings: ObservedFact[] = [];

  const pattern = /\b(?:Regex|RegexBuilder)::new\s*\(\s*"([^"]*)"\s*\)/gu;

  for (const match of text.matchAll(pattern)) {
    const regexPattern = match[1];
    const rangeMatch = /\[([a-zA-Z])-([a-zA-Z])\]/u.exec(regexPattern);

    if (rangeMatch && rangeMatch[1] > rangeMatch[2]) {
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
      continue;
    }

    const digitRangeMatch = /\[(\d)-(\d)\]/u.exec(regexPattern);

    if (digitRangeMatch && digitRangeMatch[1] > digitRangeMatch[2]) {
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

/**
 * Flags `.step_by(0)` calls that will panic at runtime.
 */
function collectStepByZeroFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.stepByZero,
    appliesTo: 'block',
    pattern: /\.step_by\s*\(\s*0\s*(?:usize|u32|u64|i32|i64)?\s*\)/gu,
  });
}

/**
 * Flags `for` loops that iterate over `.next()` result (iterates Option, not iterator).
 */
function collectIterNextInForLoopFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.iterNextInForLoop,
    appliesTo: 'block',
    pattern: /\bfor\s+\w+\s+in\s+.+?\.next\s*\(\s*\)/gu,
  });
}

/**
 * Flags range expressions where start > end (empty range).
 */
function collectEmptyRangeExpressionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.emptyRangeExpression;
  const findings: ObservedFact[] = [];

  const pattern = /(\d+)\s*\.\.=\s*(\d+)/gu;

  for (const match of text.matchAll(pattern)) {
    const start = Number(match[1]);
    const end = Number(match[2]);

    if (start > end) {
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

  const exclusivePattern = /(\d+)\s*\.\.\s*(\d+)/gu;

  for (const match of text.matchAll(exclusivePattern)) {
    const start = Number(match[1]);
    const end = Number(match[2]);

    if (start > end) {
      const lineStart = text.lastIndexOf('\n', (match.index ?? 0)) + 1;
      const beforeOnLine = text.slice(lineStart, match.index ?? 0);
      const afterMatch = (match.index ?? 0) + match[0].length;

      if (afterMatch < text.length && text[afterMatch] === '=') {
        continue;
      }

      if (!/\d/.test(beforeOnLine.replace(/\s/gu, ''))) {
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

/**
 * Flags operations that trivially evaluate to zero: x * 0, x & 0, 0 / x.
 */
function collectErasingOperationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.erasingOperation;
  const findings: ObservedFact[] = [];

  const patterns = [
    /(?:\w+\s*)\*\s*0(?:usize|u32|u64|i32|i64|i8|u8)?(?!\w)/gu,
    /0\s*\*\s*(?:\w+)/gu,
    /(?:\w+\s*)&\s*0\b(?!x)/gu,
    /0\s*\/\s*(?:\w+)/gu,
  ];

  for (const pattern of patterns) {
    for (const match of findAllMatches(text, pattern)) {
      const expression = match.matchedText;

      if (/^0\s*\*\s*0$/u.test(expression)) {
        continue;
      }

      if (!findings.some((f) => f.text === expression)) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: match.startOffset,
            endOffset: match.endOffset,
            text: expression,
          }),
        );
      }
    }
  }

  return findings;
}

/**
 * Flags binary operations with identical LHS and RHS (likely copy-paste errors).
 * Matches parenthesized logical expressions `(expr) && (expr)` and
 * simple self-operations `x + x`, `x * x`.
 */
function collectIdenticalBinaryOperandsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.identicalBinaryOperands;
  const findings: ObservedFact[] = [];

  const parenPattern = /\(\s*([^()]+?)\s*\)\s*(&&|\|\|)\s*\(\s*([^()]+?)\s*\)/gu;

  for (const match of text.matchAll(parenPattern)) {
    const lhs = match[1].trim();
    const rhs = match[3].trim();

    if (lhs === rhs) {
      const startOffset = match.index ?? 0;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset,
          endOffset: startOffset + match[0].length,
          text: match[0],
        }),
      );
    }
  }

  const selfOpPattern = /\b(\w+)\s*([-+*/%])\s*(\w+)\b/gu;

  for (const match of text.matchAll(selfOpPattern)) {
    const lhs = match[1];
    const rhs = match[3];

    if (lhs === rhs) {
      const startOffset = match.index ?? 0;

      if (!findings.some((f) => f.text === match[0])) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset,
            endOffset: startOffset + match[0].length,
            text: match[0],
          }),
        );
      }
    }
  }

  return findings;
}

/**
 * Flags common syntax-level issues: multi-char char literals.
 * Best-effort partial coverage (not a real parser).
 */
/**
 * Flags integer literals with mistyped numeric suffix (e.g., `_32` instead of `_u32`).
 * RS-E1009
 */
function collectMistypedSuffixFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.mistypedSuffix;
  const findings: ObservedFact[] = [];
  const validSuffixPattern =
    /_(?:i(?:8|16|32|64|128|size)|u(?:8|16|32|64|128|size)|f(?:32|64)|bool|char)$/u;
  const pattern = /\b\d[\d_]*_(\d+)\b/gu;

  for (const match of findAllMatches(text, pattern)) {
    const suffix = match.matchedText.slice(
      match.matchedText.indexOf('_'),
    );
    if (validSuffixPattern.test(suffix)) continue;
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

/**
 * Flags `std::mem::forget` or `std::mem::drop` on a reference (does nothing).
 * RS-E1010
 */
function collectForgetDropOnReferenceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.forgetDropOnReference,
    appliesTo: 'block',
    pattern: /\bstd::mem::(?:forget|drop)\s*\(\s*&/gu,
  });
}

/**
 * Flags `std::mem::forget` or `std::mem::drop` on a non-reference value
 * (potentially a Copy type, making the call a no-op). RS-E1011
 */
function collectForgetDropOnCopyTypeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.forgetDropOnCopyType;
  const findings: ObservedFact[] = [];

  const pattern = /\bstd::mem::(?:forget|drop)\s*\(([^)]+)\)/gu;

  for (const match of findAllMatches(text, pattern)) {
    const arg = match.matchedText;
    if (/\(\s*&/u.test(arg)) continue;
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

/**
 * Flags comparison with `f32::NAN` or `f64::NAN` using `==` or `!=`.
 * RS-E1012
 */
function collectNaNComparisonFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.nanComparison;
  const findings: ObservedFact[] = [];

  const patterns = [
    /\w+\s*[!=]=\s*f(?:32|64)::NAN\b/gu,
    /\bf(?:32|64)::NAN\s*[!=]==?\s*\w+/gu,
  ];

  for (const pattern of patterns) {
    for (const match of findAllMatches(text, pattern)) {
      if (!findings.some((f) => f.text === match.matchedText)) {
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
  }

  return findings;
}

/**
 * Flags non-octal integer arguments to `.mode()` and `from_mode()`.
 * RS-E1013
 */
function collectNonOctalPermissionsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.nonOctalPermissions;
  const findings: ObservedFact[] = [];

  const patterns = [
    /\bmode\s*\(\s*([1-9][0-9]*)\s*\)/gu,
    /\bfrom_mode\s*\(\s*([1-9][0-9]*)\s*\)/gu,
    /\bset_mode\s*\(\s*([1-9][0-9]*)\s*\)/gu,
  ];

  for (const pattern of patterns) {
    for (const match of findAllMatches(text, pattern)) {
      if (!findings.some((f) => f.text === match.matchedText)) {
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
  }

  return findings;
}

/**
 * Flags non-binding `let _ = lock.lock()`, `.read()`, `.write()` where the
 * lock guard is immediately dropped. RS-E1014
 */
function collectNonBindingLetOnLockFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.nonBindingLetOnLock,
    appliesTo: 'block',
    pattern: /\blet\s+_\s*=\s*\w+\.(?:lock|read|write)\s*\(\s*\)/gu,
  });
}

/**
 * Flags values from unit-returning collection methods used as function arguments.
 * RS-E1015 (best-effort, confidence 0.7)
 */
function collectUnitArgumentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.unitArgument;
  const findings: ObservedFact[] = [];

  const unitMethods =
    'extend|push|insert|clear|truncate|resize|remove|pop|retain|drain|sort|reverse|shuffle|swap_remove';
  const letPattern = new RegExp(
    `\\blet\\s+(\\w+)\\s*=\\s*[^;]+\\.(?:${unitMethods})\\s*\\([^)]*\\)\\s*;`,
    'gu',
  );

  for (const letMatch of text.matchAll(letPattern)) {
    const varName = letMatch[1];
    const usagePattern = new RegExp(
      `\\b\\w+\\s*\\([^)]*\\b${escapeRegex(varName)}\\b[^)]*\\)`,
      'gu',
    );

    for (const usage of text.matchAll(usagePattern)) {
      const usageIndex = usage.index ?? 0;
      const letEnd = (letMatch.index ?? 0) + letMatch[0].length;

      if (usageIndex > letEnd) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: usageIndex,
            endOffset: usageIndex + usage[0].length,
            text: usage[0],
          }),
        );
        break;
      }
    }
  }

  return findings;
}

/**
 * Flags comparison of two block expressions that both end with semicolons
 * (both evaluate to `()`). RS-E1016
 */
function collectUnitComparisonFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.unitComparison,
    appliesTo: 'block',
    pattern: /\{[^}]*;\s*\}\s*[!=]=\s*\{[^}]*;\s*\}/gu,
  });
}

/**
 * Flags transmute between integer and NonZero types (RS-E1026).
 */
function collectTransmuteIntegerToNonZeroFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const pattern = /(?:std::)?(?:mem::)?transmute::<[^>]*NonZero\w+[^>]*>\s*\(/gu;
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.transmuteIntegerToNonZero,
    appliesTo: 'block',
    pattern,
  });
}

/**
 * Flags transmute between integer and function pointer (RS-E1027).
 * Custom collector because fn ptr types can contain `->` (with `>`),
 * which breaks the standard `[^>]*` pattern used by other transmute collectors.
 */
function collectTransmuteIntToFnPtrFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.transmuteIntToFnPtr;
  const findings: ObservedFact[] = [];
  const startPattern = /\b(?:std::)?(?:mem::)?transmute::</gu;

  for (const match of findAllMatches(text, startPattern)) {
    const afterOpen = match.endOffset;
    let depth = 0;
    let closeIndex = -1;

    for (let i = afterOpen; i < text.length; i++) {
      const ch = text[i];
      if (ch === '<') {
        depth++;
      } else if (ch === '>') {
        if (depth === 0) {
          closeIndex = i;
          break;
        }
        depth--;
      }
    }

    if (closeIndex < 0) continue;

    const typeContent = text.slice(afterOpen, closeIndex);
    if (!/\bfn\s*\(/u.test(typeContent)) continue;

    const endOffset = closeIndex + 1;
    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset,
        text: text.slice(match.startOffset, endOffset),
      }),
    );
  }

  return findings;
}

/**
 * Flags transmute between integer literal/type and raw pointer (RS-E1028).
 */
function collectTransmuteIntLitToRawPtrFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const integerLit = '\\d[\\d_]*(?:_?(?:i|u|f)(?:8|16|32|64|128|size))?';
  const integerTypes = '(?:i|u)(?:8|16|32|64|128|size)';
  const pattern = new RegExp(
    `(?:std::)?(?:mem::)?transmute::<\\s*(?:${integerLit}|${integerTypes})\\s*,\\s*\\*(?:const|mut)\\s+\\w+\\s*>\\(`,
    'gu',
  );
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.transmuteIntLitToRawPtr,
    appliesTo: 'block',
    pattern,
  });
}

/**
 * Flags transmute from float or char to reference or pointer (RS-E1029).
 */
function collectTransmuteFloatCharToRefOrPtrFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const pattern = /(?:std::)?(?:mem::)?transmute::<\s*(?:f(?:32|64)|char)\s*,\s*[&*][^>]*>\s*\(/gu;
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.transmuteFloatCharToRefOrPtr,
    appliesTo: 'block',
    pattern,
  });
}

/**
 * Flags transmute between integer type and char (RS-E1030).
 */
function collectTransmuteIntegerToCharFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const integerTypes = '(?:i|u)(?:8|16|32|64|128|size)';
  const pattern = new RegExp(
    `(?:std::)?(?:mem::)?transmute::<\\s*(?:${integerTypes})\\s*,\\s*(?:char)\\s*>\\(`,
    'gu',
  );
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.transmuteIntegerToChar,
    appliesTo: 'block',
    pattern,
  });
}

/**
 * Flags transmute between numeric type and array/slice (RS-E1031).
 */
function collectTransmuteNumberToSliceOrArrayFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const numericTypes = '(?:i|u|f)(?:8|16|32|64|128|size)';
  const pattern = new RegExp(
    `(?:std::)?(?:mem::)?transmute::<\\s*(?:${numericTypes}|\\[[^\\]]*\\])\\s*,\\s*(?:${numericTypes}|\\[[^\\]]*\\])\\s*>\\(`,
    'gu',
  );
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.transmuteNumberToSliceOrArray,
    appliesTo: 'block',
    pattern,
    predicate: (match) => /\[/u.test(match.matchedText),
  });
}

/**
 * Flags transmute between tuple and array/slice (RS-E1032).
 */
function collectTransmuteTupleToSliceOrArrayFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const pattern = /(?:std::)?(?:mem::)?transmute::<\s*\([^)]+\)\s*,\s*\[[^\]]*\]\s*>\s*\(/gu;
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.transmuteTupleToSliceOrArray,
    appliesTo: 'block',
    pattern,
  });
}

/**
 * Flags print! and println! inside Display::fmt implementations (RS-E1034).
 */
function collectPrintInDisplayImplFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.printInDisplayImpl;
  const findings: ObservedFact[] = [];
  const implPattern = /\bimpl\b[^{]*\bDisplay\b/gu;

  for (const implMatch of findAllMatches(text, implPattern)) {
    const openBrace = findFunctionOpenBrace(text, implMatch.startOffset);
    if (openBrace < 0) continue;

    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const implBody = text.slice(openBrace + 1, closeBrace);
    const printPattern = /(?:println?|eprintln?)!\s*\(/gu;

    for (const printMatch of findAllMatches(implBody, printPattern)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: openBrace + 1 + printMatch.startOffset,
          endOffset: openBrace + 1 + printMatch.endOffset,
          text: printMatch.matchedText,
        }),
      );
    }
  }

  return findings;
}

/**
 * Flags async function calls from sync contexts where the returned
 * future is dropped without await (RS-E1035).
 */
function collectIgnoredFutureValueFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue;
  const findings: ObservedFact[] = [];

  // Step 1: Collect async function names
  const asyncFnNames = new Set<string>();
  const asyncFnPattern = /\basync\s+fn\s+([A-Za-z_]\w*)\s*[<(]/gu;

  for (const match of findAllMatches(text, asyncFnPattern)) {
    const nameMatch = /\basync\s+fn\s+([A-Za-z_]\w*)/u.exec(match.matchedText);
    if (nameMatch) {
      asyncFnNames.add(nameMatch[1]);
    }
  }

  if (asyncFnNames.size === 0) {
    return findings;
  }

  // Step 2: Find sync function bodies
  const syncBodies: Array<{ bodyStart: number; bodyEnd: number }> = [];
  const fnPattern = /\bfn\s+([A-Za-z_]\w*)\s*[<(]/gu;

  for (const match of findAllMatches(text, fnPattern)) {
    const beforeText = text.slice(
      Math.max(0, match.startOffset - 20),
      match.startOffset,
    ).trimEnd();
    if (beforeText.endsWith('async')) {
      continue;
    }

    const openBrace = findFunctionOpenBrace(text, match.startOffset);
    if (openBrace < 0) continue;

    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    syncBodies.push({
      bodyStart: openBrace + 1,
      bodyEnd: closeBrace,
    });
  }

  // Step 3-4: Search within sync bodies and filter
  for (const body of syncBodies) {
    const scope = text.slice(body.bodyStart, body.bodyEnd);

    for (const asyncName of asyncFnNames) {
      const callPattern = new RegExp(
        `\\b${escapeRegex(asyncName)}\\s*\\(`,
        'gu',
      );

      for (const callMatch of findAllMatches(scope, callPattern)) {
        const absoluteStart = body.bodyStart + callMatch.startOffset;
        const openParen = absoluteStart + callMatch.matchedText.length - 1;
        const closeParen = findMatchingDelimiter(
          text,
          openParen,
          '(',
          ')',
        );

        if (closeParen < 0) continue;

        // Check if followed by .await
        const afterParen = closeParen + 1;
        const afterText = text.slice(afterParen, afterParen + 12);
        if (/^\s*\.\s*await\b/u.test(afterText)) {
          continue;
        }

        // Check what precedes the call
        const beforeCall = text.slice(
          Math.max(0, absoluteStart - 40),
          absoluteStart,
        );
        const beforeTrimmed = beforeCall.trimEnd();

        // Skip if the call is an argument to another call
        if (/[(,]\s*$/u.test(beforeTrimmed)) continue;

        // Skip if qualified path
        if (/::\s*$/u.test(beforeTrimmed)) continue;

        // Skip if assignment
        if (/=\s*$/u.test(beforeTrimmed)) continue;

        // Skip if let binding
        if (/\blet\s+(?:_|\w+)\s*$/u.test(beforeTrimmed)) continue;

        // Skip if return statement
        if (/\breturn\s+$/u.test(beforeTrimmed)) continue;

        // Skip if match arm or closure arrow
        if (/=>\s*$/u.test(beforeTrimmed)) continue;

        // Skip if call is a tail expression (last in block — implicit return)
        const afterCallEnd = text.slice(closeParen + 1).trimStart();
        if (afterCallEnd.startsWith('}')) continue;

        const absoluteEnd = absoluteStart + callMatch.matchedText.length;
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: absoluteStart,
            endOffset: absoluteEnd,
            text: callMatch.matchedText,
          }),
        );
      }
    }
  }

  return findings;
}

function isInStringLiteral(text: string, offset: number): boolean {
  let inString = false;
  let inChar = false;
  for (let i = 0; i < offset; i++) {
    const c = text[i];
    if (c === '\\') {
      i++;
      continue;
    }
    if (inChar && c === '\'') {
      inChar = false;
      continue;
    }
    if (inString && c === '"') {
      inString = false;
      continue;
    }
    if (!inString && !inChar && c === '\'') {
      inChar = true;
      continue;
    }
    if (!inString && !inChar && c === '"') {
      inString = true;
      continue;
    }
  }
  return inString;
}

function collectSyntaxErrorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.syntaxError;
  const findings: ObservedFact[] = [];

  const multiCharPattern = /'[^'\\\n]{2,}'/gu;

  for (const match of findAllMatches(text, multiCharPattern)) {
    if (isInStringLiteral(text, match.startOffset)) {
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

function collectPatternsInAsyncFnBodies(options: {
  text: string;
  detector: string;
  kind: string;
  pattern: RegExp;
}): ObservedFact[] {
  const { text, detector, kind, pattern } = options;
  const findings: ObservedFact[] = [];

  for (const body of findAsyncFnBodies(text)) {
    const scope = text.slice(body.bodyStart, body.bodyEnd);

    for (const match of findAllMatches(scope, pattern)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: body.bodyStart + match.startOffset,
          endOffset: body.bodyStart + match.endOffset,
          text: match.matchedText,
        }),
      );
    }
  }

  return findings;
}

function findAsyncFnBodies(text: string): AsyncFnBody[] {
  const bodies: AsyncFnBody[] = [];
  const pattern = /\basync\s+fn\b/gu;

  for (const match of findAllMatches(text, pattern)) {
    const openBrace = findFunctionOpenBrace(text, match.startOffset);

    if (openBrace < 0) {
      continue;
    }

    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');

    if (closeBrace < 0) {
      continue;
    }

    bodies.push({
      bodyStart: openBrace + 1,
      bodyEnd: closeBrace,
    });
  }

  return bodies;
}

function findFunctionOpenBrace(source: string, fromOffset: number): number {
  let depth = 0;

  for (let index = fromOffset; index < source.length; index += 1) {
    const char = source[index];

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
  }

  return -1;
}

/**
 * Flags hashing a unit value `()`. `Hash::hash(&(), ...)` is a no-op
 * because all unit values hash identically. RS-E1017 (critical)
 */
function collectHashUnitValueFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.hashUnitValue;
  const findings: ObservedFact[] = [];

  const patterns = [
    /\bHash::hash\s*\(\s*&\(\)/gu,
    /\bstd::hash::Hash::hash\s*\(\s*&\(\)/gu,
    /\bstd::hash::Hash::hash_slice\s*\(\s*&\(\)/gu,
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

/**
 * Flags transmute from raw pointer to reference (`*const T` -> `&T`).
 * This is unsound because it creates a reference with no lifetime guarantee.
 * RS-E1018 (critical)
 */
function collectTransmutePtrToRefFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.transmutePtrToRef,
    appliesTo: 'block',
    pattern: /(?:std::)?(?:mem::)?transmute::<\s*\*(?:const|mut)\s+\w+(?:\s*,\s*)&/gu,
  });
}

/**
 * Flags transmute from reference to raw pointer (`&T` -> `*const T`).
 * Prefer `as` casts which are safer. RS-E1019 (critical)
 */
function collectTransmuteRefToPtrFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.transmuteRefToPtr,
    appliesTo: 'block',
    pattern: /(?:std::)?(?:mem::)?transmute::<\s*&(?:mut\s+)?\w+\s*,\s*\*(?:const|mut)/gu,
  });
}

/**
 * Flags transmute from one raw pointer to another (`*const T` -> `*mut T`).
 * Prefer casting through a reference to guarantee alignment/safety.
 * RS-E1020 (critical)
 */
function collectTransmutePtrToPtrFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.transmutePtrToPtr,
    appliesTo: 'block',
    pattern: /(?:std::)?(?:mem::)?transmute::<\s*\*(?:const|mut)\s+\w+(?:\s*,\s*)\*(?:const|mut)/gu,
  });
}

/**
 * Flags `std::mem::forget` or `std::mem::drop` on a non-reference value
 * that is NOT a known Drop type. On primitives (i32, bool, etc.) these
 * calls are no-ops. Best-effort detection. RS-E1021 (high)
 */
function collectForgetDropOnNonDropTypeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_CORRECTNESS_FACT_KINDS.forgetDropOnNonDropType;
  const findings: ObservedFact[] = [];

  const pattern = /\bstd::mem::(?:forget|drop)\s*\(([^)]+)\)/gu;

  for (const match of findAllMatches(text, pattern)) {
    const arg = match.matchedText;
    if (/\(\s*&/u.test(arg)) continue;

    const inner = arg.slice(arg.indexOf('(') + 1, arg.lastIndexOf(')'));

    const nonDropPattern =
      /(?:i(?:8|16|32|64|128|size)|u(?:8|16|32|64|128|size)|f(?:32|64)|bool|char|true|false)\b/u;
    if (!nonDropPattern.test(inner)) continue;

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

/**
 * Flags I/O operations where the `Result` return value is discarded.
 * Focuses on `File::open` and `File::create` which are commonly misused.
 * RS-E1023 (high)
 */
function collectUnhandledIoResultFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.unhandledIoResult,
    appliesTo: 'block',
    pattern:
      /\b(?:std::)?fs::File::(?:open|create)\s*\(/gu,
    predicate: (match) => {
      const lineStart = text.lastIndexOf('\n', match.startOffset) + 1;
      const beforeOnLine = text.slice(lineStart, match.startOffset);

      if (/\blet\s+(?:_|\w+)\s*=/u.test(beforeOnLine)) return false;
      if (/\breturn\s+/u.test(beforeOnLine)) return false;

      const afterMatch = text.slice(
        match.endOffset,
        Math.min(text.length, match.endOffset + 40),
      );

      if (/\?/u.test(afterMatch)) return false;
      if (/\.(?:unwrap|expect|await)\b/u.test(afterMatch)) return false;

      return true;
    },
  });
}

/**
 * Flags transmute between a non-pointer type T and `*T` or `&T`.
 * Example: `transmute::<u32, *const u32>`. RS-E1024 (high)
 */
function collectTransmuteTToPtrRefFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const integerTypes = '(?:i|u)(?:8|16|32|64|128|size)';
  const floatTypes = 'f(?:32|64)';
  const simpleTypes = `(?:${integerTypes}|${floatTypes}|bool|char)`;
  const pattern = new RegExp(
    `(?:std::)?(?:mem::)?transmute::<\\s*${simpleTypes}\\s*,\\s*(?:&|\\*(?:const|mut)\\s+)`,
    'gu',
  );
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.transmuteTToPtrRef,
    appliesTo: 'block',
    pattern,
  });
}

/**
 * Flags transmute between integer type and bool.
 * Example: `transmute::<i32, bool>`. RS-E1025 (high)
 */
function collectTransmuteIntegerToBoolFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const integerTypes = '(?:i|u)(?:8|16|32|64|128|size)';
  const pattern = new RegExp(
    `(?:std::)?(?:mem::)?transmute::<\\s*(?:${integerTypes})\\s*,\\s*bool\\s*>`,
    'gu',
  );
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_CORRECTNESS_FACT_KINDS.transmuteIntegerToBool,
    appliesTo: 'block',
    pattern,
  });
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}
