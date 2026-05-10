import type { Diagnostic } from '@critiq/core-diagnostics';
import type { AnalyzedFile, ObservedFact } from '@critiq/core-rules-engine';

export interface TrackedIdentifierState {
  taintedIdentifiers: Set<string>;
  sqlInterpolatedIdentifiers: Set<string>;
}

export interface SourceAnalysisSuccess {
  success: true;
  data: AnalyzedFile;
}

export interface SourceAnalysisFailure {
  success: false;
  diagnostics: Diagnostic[];
}

export type SourceAnalysisResult = SourceAnalysisSuccess | SourceAnalysisFailure;

export interface PolyglotFactCollectorContext<TState> {
  detector: string;
  state: TState;
  text: string;
  path: string;
}

export interface PolyglotAdapterDefinition<TState> {
  language: string;
  detector: string;
  validate?: (path: string, text: string) => Diagnostic | undefined;
  collectState: (text: string) => TState;
  collectFacts: (
    context: PolyglotFactCollectorContext<TState>,
  ) => ObservedFact[];
}
