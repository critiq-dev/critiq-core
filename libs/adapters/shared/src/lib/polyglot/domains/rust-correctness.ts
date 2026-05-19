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

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}
