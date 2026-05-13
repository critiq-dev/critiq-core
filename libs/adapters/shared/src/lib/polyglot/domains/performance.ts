import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';

export interface PolyglotPerformancePathOptions {
  text: string;
  path: string;
  detector: string;
}

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
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  return collectSharedPerformanceFacts(options, 'php');
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

export function collectRustPerformanceFacts(
  options: PolyglotPerformancePathOptions,
): ObservedFact[] {
  return collectSharedPerformanceFacts(options, 'rust');
}
