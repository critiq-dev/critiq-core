import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches, findMatchingDelimiter } from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const RUST_QUALITY_FACT_KINDS = {
  potentiallyIncompleteAsciiRange: 'rust.quality.potentially-incomplete-ascii-range',
  inaccurateDurationCalculation: 'rust.quality.inaccurate-duration-calculation',
  mapFollowedByCount: 'rust.quality.map-followed-by-count',
  iterNthInsteadOfGet: 'rust.quality.iter-nth-instead-of-get',
  iterCountInsteadOfLen: 'rust.quality.iter-count-instead-of-len',
  replaceSamePatternAndReplacement: 'rust.quality.replace-same-pattern-and-replacement',
  cloneOnDoubleReference: 'rust.quality.clone-on-double-reference',
  nonOwnedRcPointerIntoVec: 'rust.quality.non-owned-rc-pointer-into-vec',
  explicitSelfAssignment: 'rust.quality.explicit-self-assignment',
  envStringLiteral: 'rust.quality.env-string-literal',
  optionEnvUnwrap: 'rust.quality.option-env-unwrap',
  builtinTypeShadow: 'rust.quality.builtin-type-shadow',
  unusedEnumerateOrZipItems: 'rust.quality.unused-enumerate-or-zip-items',
  isizeUsizeOverflow: 'rust.quality.isize-usize-overflow',
  orderedIterationOnUnordered: 'rust.quality.ordered-iteration-on-unordered',
  crateInMacroDefinition: 'rust.quality.crate-in-macro-definition',
  redundantMemReplaceWithNone: 'rust.quality.redundant-mem-replace-with-none',
  redundantMemReplaceWithDefault: 'rust.quality.redundant-mem-replace-with-default',
  redundantMemReplaceWithZero: 'rust.quality.redundant-mem-replace-with-zero',
  fnPtrNullComparison: 'rust.quality.fn-ptr-null-comparison',
  possibleMissingCommaInArray: 'rust.quality.possible-missing-comma-in-array',
  nonUtf8LiteralInFromUtf8Unchecked: 'rust.quality.non-utf8-literal-in-from-utf8-unchecked',
  sizeOfValOnReference: 'rust.quality.size-of-val-on-reference',
  fnPtrToNonPointerCast: 'rust.quality.fn-ptr-to-non-pointer-cast',
  deprecatedFunctionUse: 'rust.quality.deprecated-function-use',
  approximateFloatingConstant: 'rust.quality.approximate-floating-constant',
} as const;

export interface CollectRustQualityFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectRustQualityFacts(
  options: CollectRustQualityFactsOptions,
): ObservedFact[] {
  const { text, detector, path } = options;

  if (path && isRustQualitySuppressedPath(path)) {
    return [];
  }

  return dedupeFacts([
    ...collectPotentiallyIncompleteAsciiRangeFacts(text, detector),
    ...collectInaccurateDurationCalculationFacts(text, detector),
    ...collectMapFollowedByCountFacts(text, detector),
    ...collectIterNthInsteadOfGetFacts(text, detector),
    ...collectIterCountInsteadOfLenFacts(text, detector),
    ...collectReplaceSamePatternAndReplacementFacts(text, detector),
    ...collectCloneOnDoubleReferenceFacts(text, detector),
    ...collectNonOwnedRcPointerIntoVecFacts(text, detector),
    ...collectExplicitSelfAssignmentFacts(text, detector),
    ...collectEnvStringLiteralFacts(text, detector),
    ...collectOptionEnvUnwrapFacts(text, detector),
    ...collectBuiltinTypeShadowFacts(text, detector),
    ...collectUnusedEnumerateOrZipItemsFacts(text, detector),
    ...collectIsizeUsizeOverflowFacts(text, detector),
    ...collectOrderedIterationOnUnorderedFacts(text, detector),
    ...collectCrateInMacroDefinitionFacts(text, detector),
    ...collectRedundantMemReplaceWithNoneFacts(text, detector),
    ...collectRedundantMemReplaceWithDefaultFacts(text, detector),
    ...collectRedundantMemReplaceWithZeroFacts(text, detector),
    ...collectFnPtrNullComparisonFacts(text, detector),
    ...collectPossibleMissingCommaInArrayFacts(text, detector),
    ...collectNonUtf8LiteralInFromUtf8UncheckedFacts(text, detector),
    ...collectSizeOfValOnReferenceFacts(text, detector),
    ...collectFnPtrToNonPointerCastFacts(text, detector),
    ...collectDeprecatedFunctionUseFacts(text, detector),
    ...collectApproximateFloatingConstantFacts(text, detector),
  ]);
}

function isRustQualitySuppressedPath(path: string): boolean {
  return (
    /(^|\/)tests?(\/|$)/u.test(path) ||
    /(^|\/)testdata(\/|$)/u.test(path) ||
    /(^|\/)examples?(\/|$)/u.test(path) ||
    /(^|\/)benches?(\/|$)/u.test(path) ||
    /_test\.rs$/u.test(path) ||
    /\.spec\.rs$/u.test(path)
  );
}

/**
 * Flags exclusive range `'a'..'z'` where inclusive `..=` is likely intended.
 * RS-W1086
 */
function collectPotentiallyIncompleteAsciiRangeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.potentiallyIncompleteAsciiRange;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /'[a-zA-Z0-9]'\s*\.\.\s*'[a-zA-Z0-9]'/gu,
    predicate: (match) => {
      const after = text.slice(match.endOffset);
      return !after.startsWith('=');
    },
  });
}

/**
 * Flags `subsec_micros() / 1_000` or `subsec_nanos() / 1_000` instead of
 * using `subsec_millis()` / `subsec_micros()` directly. RS-W1087
 */
function collectInaccurateDurationCalculationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.inaccurateDurationCalculation;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\b(?:\.subsec_micros\s*\(\s*\)\s*\/\s*1_000|\.subsec_nanos\s*\(\s*\)\s*\/\s*1_000)/gu,
  });
}

/**
 * Flags `.map(...).count()` where the map does not affect the count. RS-W1089
 */
function collectMapFollowedByCountFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_QUALITY_FACT_KINDS.mapFollowedByCount,
    appliesTo: 'block',
    pattern: /\.map\s*\([^)]*\)\s*\.count\s*\(\s*\)/gu,
  });
}

/**
 * Flags `.iter().nth(idx)` or `.iter_mut().nth(idx)` instead of directly
 * indexing with `.get()` / `.get_mut()`. RS-W1091
 */
function collectIterNthInsteadOfGetFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_QUALITY_FACT_KINDS.iterNthInsteadOfGet,
    appliesTo: 'block',
    pattern: /\.iter(?:_mut)?\s*\(\s*\)\s*\.nth\s*\(/gu,
  });
}

/**
 * Flags `.iter().count()` where `.len()` is more efficient. RS-W1093
 */
function collectIterCountInsteadOfLenFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_QUALITY_FACT_KINDS.iterCountInsteadOfLen,
    appliesTo: 'block',
    pattern: /\.iter\s*\(\s*\)\s*\.count\s*\(\s*\)/gu,
  });
}

/**
 * Flags `.replace()` or `.replacen()` where pattern and replacement are the
 * same string (no-op). RS-W1094
 */
function collectReplaceSamePatternAndReplacementFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.replaceSamePatternAndReplacement;
  const findings: ObservedFact[] = [];

  const pattern = /\.(?:replacen?)\s*\(\s*("[^"]*"|'[^']*')\s*,\s*\1/gu;

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

  return findings;
}

/**
 * Flags `.clone()` on a double reference inside closure patterns. RS-W1100
 */
function collectCloneOnDoubleReferenceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.cloneOnDoubleReference;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\|\s*[A-Za-z_][A-Za-z0-9_]*\s*\|[^|{}]*\.clone\s*\(\s*\)/gu,
    predicate: (match) => !match.matchedText.includes('(*'),
  });
}

/**
 * Flags non-owned Rc pointer cloned and pushed into a vector. RS-W1106
 */
function collectNonOwnedRcPointerIntoVecFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.nonOwnedRcPointerIntoVec;
  const findings: ObservedFact[] = [];

  const pattern = /Rc::new\s*\([^)]+\)/gu;

  for (const rcMatch of findAllMatches(text, pattern)) {
    const afterRc = text.slice(rcMatch.endOffset);
    const pushPattern = /\.(?:push|insert)\s*\(\s*[^)]*\.clone\s*\(\s*\)/gu;

    const pushMatch = pushPattern.exec(afterRc);
    if (pushMatch) {
      const absoluteStart = rcMatch.startOffset;
      const absoluteEnd = rcMatch.endOffset + pushMatch.index + pushMatch[0].length;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteEnd,
          text: text.slice(absoluteStart, absoluteEnd),
        }),
      );
    }
  }

  return findings;
}

/**
 * Flags `mem::replace(&mut opt, None)` where `opt.take()` is simpler. RS-W1112
 */
function collectRedundantMemReplaceWithNoneFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_QUALITY_FACT_KINDS.redundantMemReplaceWithNone,
    appliesTo: 'block',
    pattern: /\bmem::replace\s*\(\s*&mut\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*,\s*None\s*\)/gu,
  });
}

/**
 * Flags `mem::replace(&mut val, Default::default())` where `mem::take()` is
 * simpler. RS-W1113
 */
function collectRedundantMemReplaceWithDefaultFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_QUALITY_FACT_KINDS.redundantMemReplaceWithDefault,
    appliesTo: 'block',
    pattern: /\bmem::replace\s*\(\s*&mut\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*,\s*(?:Default::default\(\)|<[A-Za-z_]\w*>::default\(\))\s*\)/gu,
  });
}

/**
 * Flags `mem::replace(&mut val, 0/false/""/'' )` where `mem::take()` is
 * simpler. RS-W1114
 */
function collectRedundantMemReplaceWithZeroFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_QUALITY_FACT_KINDS.redundantMemReplaceWithZero,
    appliesTo: 'block',
    pattern: /\bmem::replace\s*\(\s*&mut\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*,\s*(?:0|false|""|'')\s*\)/gu,
  });
}

/**
 * Flags comparing a function pointer to null via address cast. RS-W1115
 */
function collectFnPtrNullComparisonFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.fnPtrNullComparison;
  const findings: ObservedFact[] = [];

  const pattern = /\b([A-Za-z_]\w*)\s+as\s+(?:i|u)(?:8|16|32|64|128|size)\b\s*==\s*(?:0|(?:std::)?ptr::null\s*\(\s*\))/gu;

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

  return findings;
}

/**
 * Flags two adjacent expressions inside `[...]` without a comma separator,
 * which likely indicates a missing comma. RS-W1121
 *
 * Heuristic: scans bracket-delimited contexts and looks for patterns like
 * `number number`, `"str" "str"`, or `ident ident` without a comma between.
 */
function collectPossibleMissingCommaInArrayFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.possibleMissingCommaInArray;
  const findings: ObservedFact[] = [];

  const arrayPattern = /\[/gu;

  for (const openMatch of findAllMatches(text, arrayPattern)) {
    const closeBracket = findMatchingDelimiter(text, openMatch.startOffset, '[', ']');
    if (closeBracket === -1) continue;

    const innerText = text.slice(openMatch.startOffset, closeBracket + 1);

    const missingCommaPattern = /(?:,\s*)?\b(?!(?:as|in|and|or|not|ref|mut|let|for|while|if|else|return|match|true|false|self|super|crate|use|mod|fn|struct|enum|trait|impl|dyn|pub|static|unsafe|async|await|move)\b)([A-Za-z_]\w*|\d+|"[^"]*"|'[^']*')\s+(?!,)([A-Za-z_]\w*|\d+|"[^"]*"|'[^']*')(?=\s*[,\]])/gu;

    for (const match of findAllMatches(innerText, missingCommaPattern)) {
      const absoluteStart = openMatch.startOffset + match.startOffset;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteStart + match.matchedText.length,
          text: match.matchedText,
        }),
      );
    }
  }

  return findings;
}

/**
 * Flags `str::from_utf8_unchecked(b"...")` where the byte literal contains
 * non-UTF-8 byte sequences (e.g., `\xff`). RS-W1122
 */
function collectNonUtf8LiteralInFromUtf8UncheckedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.nonUtf8LiteralInFromUtf8Unchecked;
  const findings: ObservedFact[] = [];

  const pattern = /\bstr::from_utf8_unchecked\s*\(\s*(b"[^"]*\\x[89a-fA-F][0-9a-fA-F][^"]*")/gu;

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

  return findings;
}

/**
 * Flags `std::mem::size_of_val(&var)` where `var` is likely a reference type,
 * which returns the size of the reference rather than the pointed-to value.
 * RS-W1123
 */
function collectSizeOfValOnReferenceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_QUALITY_FACT_KINDS.sizeOfValOnReference,
    appliesTo: 'block',
    pattern: /\bmem::size_of_val\s*\(\s*&([A-Za-z_]\w*)\s*\)/gu,
  });
}

/**
 * Flags casting a function pointer to a non-pointer type such as usize or u64.
 * RS-W1124
 */
function collectFnPtrToNonPointerCastFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.fnPtrToNonPointerCast;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\b([A-Za-z_]\w*)\s+as\s+(?:i|u)(?:8|16|32|64|128|size)\b/gu,
    predicate: (match) => {
      const name = match.matchedText.replace(/as.*$/u, '').trim();
      const targetType = match.matchedText.replace(/^.*\bas\s+/u, '').trim();
      const smallIntTypes = new Set(['u8', 'u16', 'u32', 'i8', 'i16', 'i32']);
      if (smallIntTypes.has(targetType)) return false;
      return name.length > 1 && /[a-z]/u.test(name);
    },
  });
}

// ── Rust built-in type names for shadow detection (RS-W1028) ──

const RUST_BUILTIN_TYPE_NAMES = new Set([
  'i8', 'i16', 'i32', 'i64', 'i128', 'isize',
  'u8', 'u16', 'u32', 'u64', 'u128', 'usize',
  'f32', 'f64', 'bool', 'char', 'str',
  'String', 'Vec', 'Box', 'Option', 'Result',
  'HashMap', 'HashSet', 'VecDeque', 'BTreeMap', 'BTreeSet',
  'Rc', 'Arc', 'Cell', 'RefCell', 'Mutex', 'RwLock',
  'Path', 'PathBuf', 'OsString', 'OsStr',
  'CString', 'CStr', 'Duration', 'Instant',
  'IpAddr', 'Ipv4Addr', 'Ipv6Addr', 'SocketAddr',
  'NonNull', 'NonZeroI8', 'NonZeroI16', 'NonZeroI32', 'NonZeroI64', 'NonZeroI128',
  'NonZeroU8', 'NonZeroU16', 'NonZeroU32', 'NonZeroU64', 'NonZeroU128',
  'ManuallyDrop', 'MaybeUninit',
]);

/**
 * Flags `x = x;` or `self.field = self.field;` — assigning a value to itself
 * is always a no-op and likely indicates a copy-paste bug. RS-W1013 (high)
 */
function collectExplicitSelfAssignmentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.explicitSelfAssignment;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*=\s*\1\s*;/gu,
    predicate: (match) => {
      const beforeText = text.slice(
        Math.max(0, match.startOffset - 30),
        match.startOffset,
      );
      const trimmed = beforeText.replace(/\s+$/u, '');
      if (/\blet\s*$/u.test(trimmed)) return false;
      if (/[,.(]\s*$/u.test(trimmed)) return false;
      return true;
    },
  });
}

/**
 * Flags `env!("literal")` where the argument does not look like an
 * environment variable name. Env var names use UPPER_CASE convention.
 * RS-W1015 (high)
 */
function collectEnvStringLiteralFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.envStringLiteral;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\b(?:option_)?env!\s*\(\s*"([^"]*)"\s*\)/gu,
    predicate: (match) => {
      const inner = /"([^"]*)"/u.exec(match.matchedText);
      if (!inner) return false;
      const value = inner[1];
      return !/^[A-Z][A-Z0-9_.]*$/u.test(value);
    },
  });
}

/**
 * Flags `option_env!("...").unwrap()` which panics at compile-time when the
 * env var is unset. Use `unwrap_or("default")` or `expect("msg")` instead.
 * RS-W1016 (high)
 */
function collectOptionEnvUnwrapFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_QUALITY_FACT_KINDS.optionEnvUnwrap,
    appliesTo: 'block',
    pattern: /\boption_env!\s*\([^)]*\)\s*\.\s*unwrap\s*\(\s*\)/gu,
  });
}

/**
 * Flags `let TypeName = ...` where TypeName shadows a Rust built-in type.
 * RS-W1028 (high)
 */
function collectBuiltinTypeShadowFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.builtinTypeShadow;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\blet\s+([A-Za-z_]\w*)\s*=/gu,
    predicate: (match) => {
      const name = match.matchedText
        .replace(/^let\s+/u, '')
        .replace(/\s*=$/u, '')
        .trim();
      return RUST_BUILTIN_TYPE_NAMES.has(name);
    },
  });
}

/**
 * Flags `for (idx, val) in iter.enumerate()` or `for (a, b) in a.zip(b)`
 * where the first variable is unused in the loop body. RS-W1039 (high)
 *
 * Heuristic: scans the loop body and checks if the first bind variable
 * appears as a non-member-access identifier.
 */
function collectUnusedEnumerateOrZipItemsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.unusedEnumerateOrZipItems;
  const findings: ObservedFact[] = [];

  const loopPattern = /\bfor\s+\((\w+)\s*,\s*\w+\s*\)\s+in\s+/gu;

  for (const match of findAllMatches(text, loopPattern)) {
    const bindName = match.matchedText
      .replace(/^for\s+\(/u, '')
      .replace(/,.*$/u, '')
      .trim();

    if (bindName === '_') continue;

    const afterParen = text.indexOf(')', match.endOffset);
    if (afterParen === -1) continue;

    const openBrace = findFunctionOpenBrace(text, afterParen + 1);
    if (openBrace === -1) continue;

    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace === -1) continue;

    const bodyText = text.slice(openBrace + 1, closeBrace);
    const usagePattern = new RegExp(`\\b${escapeRegex(bindName)}\\b`, 'u');

    if (!usagePattern.test(bodyText)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: closeBrace + 1,
          text: text.slice(match.startOffset, closeBrace + 1),
        }),
      );
    }
  }

  return findings;
}

/**
 * Flags `0..=isize::MAX`, `0..=usize::MAX`, or similar overflow-prone
 * enumeration with integer type maximum values. RS-W1075 (high)
 */
function collectIsizeUsizeOverflowFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.isizeUsizeOverflow;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\b(?:isize|usize|i128|u128)::MAX\b/gu,
    predicate: (match) => {
      const beforeText = text.slice(
        Math.max(0, match.startOffset - 80),
        match.startOffset,
      );
      const afterText = text.slice(
        match.endOffset,
        Math.min(text.length, match.endOffset + 80),
      );
      const wholeLine = beforeText + match.matchedText + afterText;
      return /\.\.(=)?/u.test(wholeLine);
    },
  });
}

/**
 * Flags `.sorted()` / `.sorted_by()` / `.sorted_by_key()` called on the
 * result of `.iter()` / `.into_iter()` from an unordered collection such
 * as HashMap or HashSet. RS-W1081 (high)
 *
 * Heuristic: flags any `.iter().sorted()` call chain on the assumption
 * that ordered iteration is often unnecessary on unordered collections.
 * Type-aware analysis would be more precise but is not available in the
 * text-based adapter.
 */
function collectOrderedIterationOnUnorderedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.orderedIterationOnUnordered;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\.iter\s*\(\s*\)\s*\.\s*sorted(?:_by(?:_key)?)?\s*\(/gu,
  });
}

/**
 * Flags usage of `crate::` instead of `$crate::` inside `macro_rules!`
 * definitions. RS-W1084 (high)
 */
function collectCrateInMacroDefinitionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.crateInMacroDefinition;
  const findings: ObservedFact[] = [];

  const macroPattern = /\bmacro_rules!\s*(\w+)/gu;

  for (const macroMatch of findAllMatches(text, macroPattern)) {
    const openBrace = findFunctionOpenBrace(text, macroMatch.endOffset);
    if (openBrace === -1) continue;

    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace === -1) continue;

    const macroBody = text.slice(openBrace + 1, closeBrace);

    const cratePattern = /(?<!\$)\bcrate::/gu;
    for (const crateMatch of findAllMatches(macroBody, cratePattern)) {
      const absoluteStart = openBrace + 1 + crateMatch.startOffset;
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteStart + crateMatch.matchedText.length,
          text: crateMatch.matchedText,
        }),
      );
    }
  }

  return findings;
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

/**
 * Flags usage of known deprecated Rust standard library functions, constants,
 * and types. RS-W1128 (high)
 */
const DEPRECATED_SYMBOLS: string[] = [
  'std::mem::uninitialized',
  'std::mem::forget',
  'std::sync::ONCE_INIT',
  'std::sync::atomic::ATOMIC_BOOL_INIT',
  'std::sync::atomic::ATOMIC_ISIZE_INIT',
  'std::sync::atomic::ATOMIC_USIZE_INIT',
  'std::sync::atomic::spin_loop_hint',
  'std::thread::sleep_ms',
  'std::ascii::AsciiExt',
  'std::error::Error::cause',
  'std::str::StrExt::trim_left_matches',
  'std::str::StrExt::trim_right_matches',
  'std::str::StrExt::trim_left',
  'std::str::StrExt::trim_right',
  'atomic::spin_loop_hint',
  'thread::sleep_ms',
  'mem::uninitialized',
  'mem::forget',
  'ONCE_INIT',
  'ATOMIC_BOOL_INIT',
  'ATOMIC_ISIZE_INIT',
  'ATOMIC_USIZE_INIT',
  'AsciiExt',
];

function collectDeprecatedFunctionUseFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.deprecatedFunctionUse;
  const findings: ObservedFact[] = [];

  const escapedPatterns = DEPRECATED_SYMBOLS.map(escapeRegex);
  const pattern = new RegExp(`\\b(${escapedPatterns.join('|')})\\b`, 'gu');

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

  return findings;
}

/**
 * Flags float literals that approximate known mathematical constants that
 * should use `std::f64::consts::*` or `std::f32::consts::*` instead.
 * RS-W1207 (high)
 */

interface FloatingConstant {
  value: number;
  name: string;
  tolerance: number;
}

const FLOATING_CONSTANTS: FloatingConstant[] = [
  { value: Math.PI, name: 'PI', tolerance: 0.0005 },
  { value: 2 * Math.PI, name: 'TAU', tolerance: 0.0005 },
  { value: Math.PI / 2, name: 'FRAC_PI_2', tolerance: 0.0005 },
  { value: Math.PI / 4, name: 'FRAC_PI_4', tolerance: 0.0005 },
  { value: Math.PI / 6, name: 'FRAC_PI_6', tolerance: 0.0005 },
  { value: Math.PI / 8, name: 'FRAC_PI_8', tolerance: 0.0005 },
  { value: 1 / Math.PI, name: 'FRAC_1_PI', tolerance: 0.001 },
  { value: 2 / Math.PI, name: 'FRAC_2_PI', tolerance: 0.002 },
  { value: 2 / Math.sqrt(Math.PI), name: 'FRAC_2_SQRT_PI', tolerance: 0.005 },
  { value: Math.sqrt(Math.PI), name: 'SQRT_PI', tolerance: 0.002 },
  { value: Math.E, name: 'E', tolerance: 0.0005 },
  { value: Math.LN2, name: 'LN_2', tolerance: 0.001 },
  { value: Math.LN10, name: 'LN_10', tolerance: 0.005 },
  { value: Math.LOG2E, name: 'LOG2_E', tolerance: 0.002 },
  { value: Math.LOG10E, name: 'LOG10_E', tolerance: 0.002 },
  { value: Math.SQRT1_2, name: 'FRAC_1_SQRT_2', tolerance: 0.001 },
  { value: Math.SQRT2, name: 'SQRT_2', tolerance: 0.001 },
];

function collectApproximateFloatingConstantFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_QUALITY_FACT_KINDS.approximateFloatingConstant;
  const findings: ObservedFact[] = [];

  const floatPattern = /(?<![A-Za-z0-9_.])(\d+\.\d*[eE][+-]?\d+|\d+\.\d+|\d*\.\d+)(?![A-Za-z0-9_.])/gu;

  for (const match of findAllMatches(text, floatPattern)) {
    const literalValue = parseFloat(match.matchedText);

    if (Number.isNaN(literalValue) || !Number.isFinite(literalValue)) continue;

    for (const constant of FLOATING_CONSTANTS) {
      if (
        Math.abs(literalValue - constant.value) <= constant.tolerance
      ) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: match.startOffset,
            endOffset: match.endOffset,
            text: match.matchedText,
            props: {
              constantName: constant.name,
            },
          }),
        );
        break;
      }
    }
  }

  return findings;
}
