import { extname } from 'node:path';

import type { CheckScanProfileTimings } from './scan-profile';

export interface BenchmarkSummary {
  totalFiles: number;
  filesByLanguage: Record<string, number>;
  filesByExtension: Record<string, number>;
  totalRules: number;
  totalFindings: number;
  scopeMode: string;
}

export interface BenchmarkFinalizeInput {
  totalFiles: number;
  totalRules: number;
  totalFindings: number;
  scopeMode: string;
}

export interface AdapterBenchmark {
  totalMs: number;
  fileCount: number;
  minMs: number;
  maxMs: number;
  avgMs: number;
  medianMs: number;
}

export interface LanguageBenchmark {
  totalMs: number;
  fileCount: number;
  minMs: number;
  maxMs: number;
  avgMs: number;
  medianMs: number;
}

export interface RuleBenchmark {
  totalMs: number;
  evalCount: number;
  matchCount: number;
}

export interface FileBenchmarkEntry {
  path: string;
  analyzeMs: number;
  adapter: string;
  language: string;
}

export interface RuleBenchmarkEntry {
  ruleId: string;
  totalMs: number;
  evalCount: number;
  matchCount: number;
}

export interface PreloadBenchmark {
  fileCount: number;
  totalMs: number;
}

export interface BenchmarkReport {
  version: 1;
  generatedAt: string;
  summary: BenchmarkSummary;
  phases: CheckScanProfileTimings;
  adapters: Record<string, AdapterBenchmark>;
  languages: Record<string, LanguageBenchmark>;
  rules: Record<string, RuleBenchmark>;
  slowestFiles: FileBenchmarkEntry[];
  slowestRules: RuleBenchmarkEntry[];
  preload: PreloadBenchmark;
}

interface AdapterFileTiming {
  adapterName: string;
  language: string;
  filePath: string;
  elapsedMs: number;
}

interface RuleTiming {
  ruleId: string;
  elapsedMs: number;
  matched: boolean;
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 !== 0
    ? sorted[mid]
    : (sorted[mid - 1] + sorted[mid]) / 2;
}

function computeAdapterBenchmark(
  timings: AdapterFileTiming[],
): Record<string, AdapterBenchmark> {
  const byAdapter = new Map<string, number[]>();

  for (const timing of timings) {
    const times = byAdapter.get(timing.adapterName) ?? [];
    times.push(timing.elapsedMs);
    byAdapter.set(timing.adapterName, times);
  }

  const result: Record<string, AdapterBenchmark> = {};

  for (const [name, times] of byAdapter) {
    const totalMs = times.reduce((sum, t) => sum + t, 0);
    result[name] = {
      totalMs: Math.round(totalMs * 100) / 100,
      fileCount: times.length,
      minMs: Math.round(Math.min(...times) * 100) / 100,
      maxMs: Math.round(Math.max(...times) * 100) / 100,
      avgMs: Math.round((totalMs / times.length) * 100) / 100,
      medianMs: Math.round(median(times) * 100) / 100,
    };
  }

  return result;
}

function computeLanguageBenchmark(
  timings: AdapterFileTiming[],
): Record<string, LanguageBenchmark> {
  const byLanguage = new Map<string, number[]>();

  for (const timing of timings) {
    const times = byLanguage.get(timing.language) ?? [];
    times.push(timing.elapsedMs);
    byLanguage.set(timing.language, times);
  }

  const result: Record<string, LanguageBenchmark> = {};

  for (const [name, times] of byLanguage) {
    const totalMs = times.reduce((sum, t) => sum + t, 0);
    result[name] = {
      totalMs: Math.round(totalMs * 100) / 100,
      fileCount: times.length,
      minMs: Math.round(Math.min(...times) * 100) / 100,
      maxMs: Math.round(Math.max(...times) * 100) / 100,
      avgMs: Math.round((totalMs / times.length) * 100) / 100,
      medianMs: Math.round(median(times) * 100) / 100,
    };
  }

  return result;
}

export class BenchmarkCollector {
  private readonly adapterTimings: AdapterFileTiming[] = [];
  private readonly ruleTimings: RuleTiming[] = [];
  private preloadFileCount = 0;
  private preloadTotalMs = 0;

  recordAdapterAnalyze(
    adapterName: string,
    language: string,
    filePath: string,
    elapsedMs: number,
  ): void {
    this.adapterTimings.push({
      adapterName,
      language,
      filePath,
      elapsedMs: Math.round(elapsedMs * 100) / 100,
    });
  }

  recordRuleEval(ruleId: string, elapsedMs: number, matched: boolean): void {
    this.ruleTimings.push({
      ruleId,
      elapsedMs: Math.round(elapsedMs * 100) / 100,
      matched,
    });
  }

  recordPreload(fileCount: number, totalMs: number): void {
    this.preloadFileCount = fileCount;
    this.preloadTotalMs = Math.round(totalMs * 100) / 100;
  }

  finalize(
    input: BenchmarkFinalizeInput,
    phases: CheckScanProfileTimings,
  ): BenchmarkReport {
    const adapters = computeAdapterBenchmark(this.adapterTimings);
    const languages = computeLanguageBenchmark(this.adapterTimings);

    const filesByLanguage: Record<string, number> = {};
    const filesByExtension: Record<string, number> = {};
    for (const timing of this.adapterTimings) {
      filesByLanguage[timing.language] =
        (filesByLanguage[timing.language] ?? 0) + 1;
      const ext = extname(timing.filePath).toLowerCase() || '(none)';
      filesByExtension[ext] = (filesByExtension[ext] ?? 0) + 1;
    }

    const summary: BenchmarkSummary = {
      totalFiles: input.totalFiles,
      filesByLanguage,
      filesByExtension,
      totalRules: input.totalRules,
      totalFindings: input.totalFindings,
      scopeMode: input.scopeMode,
    };

    const byRule = new Map<string, { totalMs: number; evalCount: number; matchCount: number }>();

    for (const timing of this.ruleTimings) {
      const existing = byRule.get(timing.ruleId) ?? {
        totalMs: 0,
        evalCount: 0,
        matchCount: 0,
      };
      existing.totalMs += timing.elapsedMs;
      existing.evalCount += 1;
      if (timing.matched) {
        existing.matchCount += 1;
      }
      byRule.set(timing.ruleId, existing);
    }

    const rules: Record<string, RuleBenchmark> = {};

    for (const [ruleId, data] of byRule) {
      rules[ruleId] = {
        totalMs: Math.round(data.totalMs * 100) / 100,
        evalCount: data.evalCount,
        matchCount: data.matchCount,
      };
    }

    const slowestFiles = [...this.adapterTimings]
      .sort((a, b) => b.elapsedMs - a.elapsedMs)
      .slice(0, 10)
      .map((timing) => ({
        path: timing.filePath,
        analyzeMs: timing.elapsedMs,
        adapter: timing.adapterName,
        language: timing.language,
      }));

    const slowestRules = [...byRule.entries()]
      .sort(([, a], [, b]) => b.totalMs - a.totalMs)
      .slice(0, 10)
      .map(([ruleId, data]) => ({
        ruleId,
        totalMs: Math.round(data.totalMs * 100) / 100,
        evalCount: data.evalCount,
        matchCount: data.matchCount,
      }));

    return {
      version: 1,
      generatedAt: new Date().toISOString(),
      summary,
      phases,
      adapters,
      languages,
      rules,
      slowestFiles,
      slowestRules,
      preload: {
        fileCount: this.preloadFileCount,
        totalMs: this.preloadTotalMs,
      },
    };
  }
}
