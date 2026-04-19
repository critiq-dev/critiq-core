import type { AnalyzedFile } from '@critiq/core-rules-engine';

import { type ProjectAnalysisOptions, createFileContexts } from './context';
import {
  emitDuplicateCodeFacts,
  emitFrontendOnlyAuthorizationFacts,
  emitLogicChangeWithoutTestsFacts,
  emitMissingAuthorizationFacts,
  emitMissingBatchFacts,
  emitMissingOwnershipFacts,
  emitMissingTestsFacts,
  emitRepeatedIoFacts,
  emitTightCouplingFacts,
} from './fact-emitters';

export function augmentProjectFacts(
  analyzedFiles: readonly AnalyzedFile[],
  options: ProjectAnalysisOptions,
): AnalyzedFile[] {
  const contexts = createFileContexts(analyzedFiles);

  emitMissingAuthorizationFacts(contexts);
  emitMissingOwnershipFacts(contexts);
  emitFrontendOnlyAuthorizationFacts(contexts);
  emitRepeatedIoFacts(contexts);
  emitMissingBatchFacts(contexts);
  emitDuplicateCodeFacts(contexts);
  emitTightCouplingFacts(contexts);
  emitMissingTestsFacts(contexts);

  if (options.scopeMode === 'diff') {
    emitLogicChangeWithoutTestsFacts(contexts);
  }

  return [...analyzedFiles];
}
