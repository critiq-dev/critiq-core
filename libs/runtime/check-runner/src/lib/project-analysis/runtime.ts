import type { AnalyzedFile } from '@critiq/core-rules-engine';

import { type ProjectAnalysisOptions, createFileContexts } from './context';
import {
  emitDuplicateCodeFacts,
  emitFrontendOnlyAuthorizationFacts,
  emitLogicChangeWithoutTestsFacts,
  emitMissingAuthorizationFacts,
  emitMissingBatchFacts,
  emitMissingNextErrorBoundaryFacts,
  emitMissingOwnershipFacts,
  emitMissingTestsFacts,
  emitRepeatedIoFacts,
  emitTightCouplingFacts,
} from './fact-emitters';
import { appendDependencyFacts } from './dependencies';

export function augmentProjectFacts(
  analyzedFiles: readonly AnalyzedFile[],
  options: ProjectAnalysisOptions,
): AnalyzedFile[] {
  const projectAnalysisEligibleFiles = analyzedFiles.filter(
    (file) => file.language === 'javascript' || file.language === 'typescript',
  );
  const contexts = createFileContexts(projectAnalysisEligibleFiles);

  emitMissingAuthorizationFacts(contexts);
  emitMissingOwnershipFacts(contexts);
  emitFrontendOnlyAuthorizationFacts(contexts);
  emitRepeatedIoFacts(contexts);
  emitMissingBatchFacts(contexts);
  emitDuplicateCodeFacts(contexts);
  emitTightCouplingFacts(contexts);
  emitMissingNextErrorBoundaryFacts(contexts);
  emitMissingTestsFacts(contexts, options.availableTestPaths);

  if (options.scopeMode === 'diff') {
    emitLogicChangeWithoutTestsFacts(
      contexts,
      options.availableChangedTestPaths,
    );
  }

  appendDependencyFacts(analyzedFiles, options.dependencyFacts ?? []);

  return [...analyzedFiles];
}
