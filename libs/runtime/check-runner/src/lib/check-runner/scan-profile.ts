export interface CheckScanProfileTimings {
  scopeResolveMs: number;
  configLoadMs: number;
  catalogLoadMs: number;
  filterPathsMs: number;
  filePreloadMs: number;
  analyzeMs: number;
  projectAnalysisMs: number;
  ruleEvalMs: number;
  secretsScanMs: number;
  totalMs: number;
}

export interface CheckScanProfile {
  timings: CheckScanProfileTimings;
}

export class ScanPhaseTimer {
  private readonly startedAt = performance.now();
  private readonly marks = new Map<string, number>();

  mark(name: string): void {
    this.marks.set(name, performance.now());
  }

  elapsedMs(fromMark: string, toMark?: string): number {
    const from = this.marks.get(fromMark);

    if (from === undefined) {
      return 0;
    }

    const to = toMark ? this.marks.get(toMark) : performance.now();

    if (to === undefined) {
      return 0;
    }

    return Math.max(0, to - from);
  }

  snapshot(): CheckScanProfileTimings {
    const scopeResolveMs = this.elapsedMs('scope:start', 'scope:end');
    const configLoadMs = this.elapsedMs('config:start', 'config:end');
    const catalogLoadMs = this.elapsedMs('catalog:start', 'catalog:end');
    const filterPathsMs = this.elapsedMs('filter:start', 'filter:end');
    const filePreloadMs = this.elapsedMs('preload:start', 'preload:end');
    const analyzeMs = this.elapsedMs('analyze:start', 'analyze:end');
    const projectAnalysisMs = this.elapsedMs('project:start', 'project:end');
    const ruleEvalMs = this.elapsedMs('ruleEval:start', 'ruleEval:end');
    const secretsScanMs = this.elapsedMs('secrets:start', 'secrets:end');
    const endAt = this.marks.get('total:end') ?? performance.now();

    return {
      scopeResolveMs,
      configLoadMs,
      catalogLoadMs,
      filterPathsMs,
      filePreloadMs,
      analyzeMs,
      projectAnalysisMs,
      ruleEvalMs,
      secretsScanMs,
      totalMs: Math.max(0, endAt - this.startedAt),
    };
  }

  finish(): CheckScanProfile {
    this.mark('total:end');

    return {
      timings: this.snapshot(),
    };
  }
}
