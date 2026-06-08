import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';
import type { TrackedIdentifierState } from '../types';

export interface PolyglotPerformancePathOptions {
  text: string;
  path: string;
  detector: string;
}

export interface PhpPerformanceFactsOptions extends PolyglotPerformancePathOptions {
  state?: TrackedIdentifierState;
  matchesTainted?: (
    expression: string,
    state: TrackedIdentifierState,
  ) => boolean;
}

export const PHP_PERFORMANCE_FACT_KINDS = {
  noRegexConstructionInLoop: 'php.performance.no-regex-construction-in-loop',
  noSyncFsInRequestPath: 'php.performance.no-sync-fs-in-request-path',
  expensiveLoopCondition: 'php.performance.expensive-loop-condition',
  noUnboundedConcurrency: 'php.performance.no-unbounded-concurrency',
} as const;

function collectSharedPerformanceFacts(
  options: PolyglotPerformancePathOptions,
  languagePrefix: string,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: `${languagePrefix}.performance.no-regex-construction-in-loop`,
      pattern: /\b(?:for|while)\b[\s\S]{0,200}\b(?:new\s+RegExp|regexp\.Compile|Regex::new)\s*\(/g,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: `${languagePrefix}.performance.no-sync-fs-in-request-path`,
      pattern:
        /\b(?:req|request|ctx|context)\b[\s\S]{0,260}\b(?:ReadFileSync|WriteFileSync|readFileSync|writeFileSync|os\.ReadFile|Files\.(?:readAllBytes|write)|File::open|std::fs::(?:read_to_string|read|write))\b/g,
      appliesTo: 'function',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: `${languagePrefix}.performance.no-unbounded-concurrency`,
      pattern:
        /\b(?:Promise\.all|CompletableFuture\.allOf|asyncio\.gather|Task\.WhenAll|tokio::join!|futures::future::join_all)\s*\([^)]*(?:map|items|records|users|rows|list|iter)\b[^)]*\)/g,
      appliesTo: 'block',
    }),
  ];
}

export function collectGoPerformanceFacts(
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  return collectSharedPerformanceFacts(options, 'go');
}

export function collectJavaPerformanceFacts(
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  return collectSharedPerformanceFacts(options, 'java');
}

export function collectPhpPerformanceFacts(
  options: PhpPerformanceFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: PHP_PERFORMANCE_FACT_KINDS.noRegexConstructionInLoop,
      pattern:
        /\b(?:for|while)\b[\s\S]{0,300}\bpreg_(?:match|match_all|replace|replace_callback|filter|grep|split)\s*\(/gu,
      appliesTo: 'block',
    }),
    ...collectPhpSyncFsInRequestPathFacts(options),
    ...collectMatchedFacts({
      text,
      detector,
      kind: PHP_PERFORMANCE_FACT_KINDS.expensiveLoopCondition,
      pattern:
        /\b(?:for|while)\s*\([\s\S]{0,240}?\b(?:count|sizeof|strlen|preg_match|preg_match_all|array_sum|in_array|file_get_contents|file_exists|glob)\s*\(/gu,
      appliesTo: 'block',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: PHP_PERFORMANCE_FACT_KINDS.noUnboundedConcurrency,
      appliesTo: 'block',
      pattern:
        /\b(?:GuzzleHttp\\Promise\\(?:all|unwrap)|Amp\\Promise\\all)\s*\(\s*\$\w+/gu,
    }),
  ];
}

const phpSyncFsCallPattern =
  /\b(?:file_get_contents|fopen|readfile|file|scandir|glob)\s*\(/gu;

function collectPhpSyncFsInRequestPathFacts(
  options: PhpPerformanceFactsOptions,
): ObservedFact[] {
  const { text, detector, state, matchesTainted } = options;

  if (!state || !matchesTainted) {
    return [];
  }

  return collectSnippetFacts({
    text,
    detector,
    kind: PHP_PERFORMANCE_FACT_KINDS.noSyncFsInRequestPath,
    pattern: phpSyncFsCallPattern,
    state,
    appliesTo: 'block',
    predicate: (snippet, scanState) =>
      isPhpSyncFsInRequestHandler(text, snippet.startOffset) &&
      matchesTainted(snippet.text, scanState),
  });
}

function isPhpSyncFsInRequestHandler(
  text: string,
  callStartOffset: number,
): boolean {
  const prefix = text.slice(0, callStartOffset);
  const functionStart = prefix.lastIndexOf('function');

  if (functionStart < 0) {
    return false;
  }

  return /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/u.test(
    text.slice(functionStart, callStartOffset),
  );
}

export function collectPythonPerformanceFacts(
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  return collectSharedPerformanceFacts(options, 'py');
}

export function collectRubyPerformanceFacts(
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  return collectSharedPerformanceFacts(options, 'ruby');
}

export const RUST_PERFORMANCE_FACT_KINDS = {
  singleCharStringLiteralPattern:
    'rust.performance.single-char-string-literal-pattern',
} as const;

function collectRustSingleCharStringLiteralFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_PERFORMANCE_FACT_KINDS.singleCharStringLiteralPattern,
    pattern:
      /\.(?:find|rfind|contains|starts_with|ends_with|strip_prefix|strip_suffix|trim_start_matches|trim_end_matches|trim_matches|split|rsplit|splitn|rsplitn|split_terminator|matches|rmatches|match_indices|rmatch_indices|replace|replacen)\s*\(\s*"(?:[^"\\]|\\.)"\s*[,)]/g,
    appliesTo: 'block',
  });
}

export function collectRustPerformanceFacts(
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  const { text, detector } = options;
  return [
    ...collectSharedPerformanceFacts(options, 'rust'),
    ...collectRustSingleCharStringLiteralFacts(text, detector),
  ];
}
