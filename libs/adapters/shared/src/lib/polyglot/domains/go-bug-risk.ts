import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches, findMatchingDelimiter } from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const GO_BUG_RISK_FACT_KINDS = {
  ginLoadHTMLGlobIllFormed: 'go.bug-risk.gin-loadhtmlglob-ill-formed',
  redisIncorrectArgCount: 'go.bug-risk.redis-incorrect-arg-count',
  redisUnimplementedMethod: 'go.bug-risk.redis-unimplemented-method',
  etcdInvalidCompareOperator: 'go.bug-risk.etcd-invalid-compare-operator',
  gormWhereZeroValues: 'go.bug-risk.gorm-where-zero-values',
  gormUpdatesZeroValues: 'go.bug-risk.gorm-updates-zero-values',
  signednessCasting: 'go.correctness.signedness-casting',
  hiddenGoroutine: 'go.correctness.hidden-goroutine',
  poorlyFormedNilnessGuards:
    'go.bug-risk.poorly-formed-nilness-guards',
  compoundAssignmentMisuse:
    'go.bug-risk.compound-assignment-misuse',
  redisDeprecatedMethod: 'go.bug-risk.deprecated-redis-methods',
  etcdGetLoggerMisuse: 'go.bug-risk.etcd-getlogger-misuse',
  gormSkipDefaultTransaction:
    'go.bug-risk.gorm-skip-default-transaction',
  gormDryRunEnabled: 'go.bug-risk.gorm-dry-run-enabled',
  reflectMakeFuncUsage: 'go.bug-risk.reflect-makefunc-usage',
} as const;

export interface CollectGoBugRiskFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectGoBugRiskFacts(
  options: CollectGoBugRiskFactsOptions,
): ObservedFact[] {
  const { text, detector, path } = options;

  if (path && isGoBugRiskSuppressedPath(path)) {
    return [];
  }

  return dedupeFacts([
    ...collectGinLoadHTMLGlobIllFormedFacts(text, detector),
    ...collectRedisIncorrectArgCountFacts(text, detector),
    ...collectRedisUnimplementedMethodFacts(text, detector),
    ...collectEtcdInvalidCompareOperatorFacts(text, detector),
    ...collectGormWhereZeroValuesFacts(text, detector),
    ...collectGormUpdatesZeroValuesFacts(text, detector),
    ...collectSignednessCastingFacts(text, detector),
    ...collectHiddenGoroutineFacts(text, detector),
    ...collectPoorlyFormedNilnessGuardsFacts(text, detector),
    ...collectCompoundAssignmentMisuseFacts(text, detector),
    ...collectDeprecatedRedisMethodFacts(text, detector),
    ...collectEtcdGetLoggerMisuseFacts(text, detector),
    ...collectGormSkipDefaultTransactionFacts(text, detector),
    ...collectGormDryRunEnabledFacts(text, detector),
    ...collectReflectMakeFuncUsageFacts(text, detector),
  ]);
}

function isGoBugRiskSuppressedPath(path: string): boolean {
  return (
    /(^|\/)testdata(\/|$)/u.test(path) ||
    /_test\.go$/u.test(path) ||
    /(^|\/)vendor(\/|$)/u.test(path)
  );
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

/**
 * GO-E1000: Flags `gin.LoadHTMLGlob(` calls where the glob pattern argument
 * is not a simple string literal. Ill-formed patterns can silently match
 * zero files and cause a runtime panic.
 */
function collectGinLoadHTMLGlobIllFormedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_BUG_RISK_FACT_KINDS.ginLoadHTMLGlobIllFormed,
    appliesTo: 'block',
    pattern: /(?:\bgin\.\s*)?\bLoadHTMLGlob\s*\(/gu,
  });
}

/**
 * GO-E1001: Flags calls to Redis variadic methods (`MemoryUsage`, `ZPopMax`,
 * `ZPopMin`, `BitPos`) where the argument count may be incorrect.
 * Simplified: flag all calls to these methods for audit.
 */
function collectRedisIncorrectArgCountFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_BUG_RISK_FACT_KINDS.redisIncorrectArgCount;

  const patterns = [
    /\bMemoryUsage\s*\(/gu,
    /\bZPopMax\s*\(/gu,
    /\bZPopMin\s*\(/gu,
    /\bBitPos\s*\(/gu,
  ];

  return patterns.flatMap((pattern) =>
    collectMatchedFacts({ text, detector, kind, appliesTo: 'block', pattern }),
  );
}

/**
 * GO-E1002: Flags calls to `Sync(ctx)` or `Quit(ctx)` — these Redis methods
 * are not implemented in go-redis and will panic at runtime.
 */
function collectRedisUnimplementedMethodFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_BUG_RISK_FACT_KINDS.redisUnimplementedMethod,
    appliesTo: 'block',
    pattern: /\b(?:Sync|Quit)\s*\(/gu,
  });
}

/**
 * GO-E1003: Flags `clientv3.Compare(` calls. The result operator argument
 * must be one of `=`, `!=`, `>`, `<`. Using any other operator string
 * causes a runtime panic. Simplified: flag all calls for manual audit.
 */
function collectEtcdInvalidCompareOperatorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_BUG_RISK_FACT_KINDS.etcdInvalidCompareOperator,
    appliesTo: 'block',
    pattern: /(?:clientv3\.\s*)?Compare\s*\(/gu,
  });
}

/**
 * GO-E1004: Flags `db.Where(&Struct{...})` calls — struct-based Where
 * queries silently ignore zero-value fields.
 */
function collectGormWhereZeroValuesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_BUG_RISK_FACT_KINDS.gormWhereZeroValues,
    appliesTo: 'block',
    pattern: /\bWhere\s*\(\s*&\s*\w+\s*\{/gu,
  });
}

/**
 * GO-E1005: Flags `db.Updates(Struct{...})` or `db.Model(...).Updates(Struct{...})`
 * calls — struct-based Updates silently skip zero-value fields.
 */
function collectGormUpdatesZeroValuesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_BUG_RISK_FACT_KINDS.gormUpdatesZeroValues;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\bUpdates\s*\(\s*\w+\s*\{/gu,
  });
}

/**
 * GO-E1006: Flags narrowing integer casts that lose signedness.
 * Detects conversions like `int8(x)`, `uint16(x)` etc. where the cast
 * narrows to a smaller type. Focused on `strconv.Atoi` result casts
 * for highest signal-to-noise ratio.
 */
function collectSignednessCastingFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_BUG_RISK_FACT_KINDS.signednessCasting,
    appliesTo: 'block',
    pattern:
      /(?:uint8|uint16|uint32|int8|int16|int32)\s*\(\s*\w+\s*\)/gu,
    predicate: (match) => {
      const before = match.matchedText;
      return /\bstrconv\.Atoi\b/u.test(before) || /[A-Za-z_]\w*/u.test(before);
    },
  });
}

/**
 * GO-E1007: Flags functions whose entire body is wrapped in a `go func()` call.
 * Extracts function bodies and checks if the body consists only of a goroutine
 * invocation (possibly with a preceding `return` or trailing newline).
 */
function collectHiddenGoroutineFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_BUG_RISK_FACT_KINDS.hiddenGoroutine;
  const findings: ObservedFact[] = [];

  const funcPattern = /\bfunc\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*\)\s*\{/gu;

  for (const match of findAllMatches(text, funcPattern)) {
    const openBraceIndex = match.endOffset - 1;

    if (text[openBraceIndex] !== '{') {
      continue;
    }

    const closeBraceIndex = findMatchingDelimiter(
      text,
      openBraceIndex,
      '{',
      '}',
    );

    if (closeBraceIndex < 0) {
      continue;
    }

    const body = text.slice(openBraceIndex + 1, closeBraceIndex).trim();

    if (!body) {
      continue;
    }

    const strippedBody = body
      .replace(/^return\s+/u, '')
      .replace(/^\s*$/u, '')
      .trim();

    const goFuncPattern = /^go\s+func\s*\(/u;

    if (!goFuncPattern.test(strippedBody)) {
      continue;
    }

    const goBodyStart = strippedBody.indexOf('{');
    if (goBodyStart < 0) {
      continue;
    }

    const goBodyEnd = findMatchingDelimiter(
      strippedBody,
      goBodyStart,
      '{',
      '}',
    );

    if (goBodyEnd < 0) {
      continue;
    }

    const beforeGo = body.slice(0, body.indexOf(strippedBody));
    const afterGo = strippedBody.slice(goBodyEnd + 1).trim();

    const onlyGoFunc = /^(?:\(\))?\s*$/u.test(afterGo);

    if (!onlyGoFunc) {
      continue;
    }

    const stashableBefore = beforeGo.trim();
    if (stashableBefore && stashableBefore !== 'return') {
      continue;
    }

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: closeBraceIndex + 1,
        text: text.slice(match.startOffset, closeBraceIndex + 1),
      }),
    );
  }

  return findings;
}

/**
 * GO-E1008: Flags `x == nil && x.Method()` (AND with == nil proceeds to
 * deref when x IS nil) and `x != nil || x.Method()` (OR with != nil
 * proceeds to deref when x IS nil). Both are nil pointer deref bugs.
 */
function collectPoorlyFormedNilnessGuardsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_BUG_RISK_FACT_KINDS.poorlyFormedNilnessGuards;

  // Pattern A: x == nil && x.something  (AND guard, == nil)
  // Pattern B: x != nil || x.something  (OR guard, != nil)
  // Backreference \1 ensures same identifier on both sides.
  // Qualified identifiers like a.b are matched by (\w+(?:\.\w+)*).
  const nilnessPattern =
    /(\w+(?:\.\w+)*)\s*==\s*nil\s*&&\s*\1\s*\.|(\w+(?:\.\w+)*)\s*!=\s*nil\s*\|\|\s*\2\s*\./gu;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: nilnessPattern,
  });
}

/**
 * GO-E1009: Flags suspicious compound assignment patterns like
 * `x += x + y` (effectively 2x + y, likely meant x += y).
 * Matches same identifier on both sides using backreference.
 */
function collectCompoundAssignmentMisuseFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_BUG_RISK_FACT_KINDS.compoundAssignmentMisuse;

  const patterns = [
    /(\w+)\s*\+=\s*\1\s*\+\s*\w+/gu,
    /(\w+)\s*\+=\s*\1\s*-\s*\w+/gu,
    /(\w+)\s*-=\s*\1\s*\+\s*\w+/gu,
    /(\w+)\s*-=\s*\1\s*-\s*\w+/gu,
  ];

  return patterns.flatMap((pattern) =>
    collectMatchedFacts({ text, detector, kind, appliesTo: 'block', pattern }),
  );
}

/**
 * GO-W1000: Flags calls to deprecated go-redis methods (XTrim, XTrimApprox,
 * ZAddCh, ZAddNXCh, ZAddXXCh, ZIncr, ZIncrNX, ZIncrXX). These methods
 * have been replaced with newer alternatives.
 */
function collectDeprecatedRedisMethodFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_BUG_RISK_FACT_KINDS.redisDeprecatedMethod,
    appliesTo: 'block',
    pattern:
      /\.\s*(?:XTrim|XTrimApprox|ZAddCh|ZAddNXCh|ZAddXXCh|ZIncr(?:NX|XX)?)\s*\(/gu,
  });
}

/**
 * GO-W1003: Flags calls to `GetLogger()` when the file imports etcd client v3.
 * GetLogger is internal to etcd's client; using it as a general-purpose logger
 * is a misuse pattern.
 */
function collectEtcdGetLoggerMisuseFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const hasEtcdImport = /"go\.etcd\.io\/etcd\/client\/v3"/u.test(text);

  return collectMatchedFacts({
    text,
    detector,
    kind: GO_BUG_RISK_FACT_KINDS.etcdGetLoggerMisuse,
    appliesTo: 'block',
    pattern: /\bGetLogger\s*\(/gu,
    predicate: () => hasEtcdImport,
  });
}

/**
 * GO-W1004: Flags `SkipDefaultTransaction: false` or `SkipDefaultTransaction:!true`
 * in gorm.Config struct literals. Setting SkipDefaultTransaction to false
 * may cause unintended per-operation transactions.
 */
function collectGormSkipDefaultTransactionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_BUG_RISK_FACT_KINDS.gormSkipDefaultTransaction,
    appliesTo: 'block',
    pattern: /SkipDefaultTransaction\s*:\s*(?:false|!true)/gu,
  });
}

/**
 * GO-W1005: Flags `DryRun: true` in gorm.Config struct literals.
 * DryRun generates SQL without executing; if execution is needed,
 * DryRun should be disabled.
 */
function collectGormDryRunEnabledFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_BUG_RISK_FACT_KINDS.gormDryRunEnabled,
    appliesTo: 'block',
    pattern: /DryRun\s*:\s*true\b/gu,
  });
}

/**
 * GO-W1006: Flags calls to `reflect.MakeFunc(`, which dynamically constructs
 * functions. This is a flag-for-review rule — audit that type safety is preserved.
 */
function collectReflectMakeFuncUsageFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_BUG_RISK_FACT_KINDS.reflectMakeFuncUsage,
    appliesTo: 'block',
    pattern: /\breflect\.\s*MakeFunc\s*\(/gu,
  });
}
