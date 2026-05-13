import type { AnalyzedFile } from '@critiq/core-rules-engine';

import { type ProjectAnalysisOptions, createFileContexts } from './context';
import {
  emitDuplicateCodeFacts,
  emitBarrelCycleFacts,
  emitDeadExportFacts,
  emitFrontendOnlyAuthorizationFacts,
  emitLogicChangeWithoutTestsFacts,
  emitNPlusOneAwaitInMapFacts,
  emitMissingAuthorizationFacts,
  emitMissingBatchFacts,
  emitMissingEdgeCaseTestsFacts,
  emitMissingNextErrorBoundaryFacts,
  emitMissingOwnershipFacts,
  emitRedundantNetworkFetchFacts,
  emitMissingTestsFacts,
  emitProductionTestBoundaryFacts,
  emitRepeatedIoFacts,
  emitTightCouplingFacts,
  emitUnstableCacheKeyFacts,
  emitWidePublicSurfaceFacts,
} from './fact-emitters';
import { appendDependencyFacts } from './dependencies';

export function augmentProjectFacts(
  analyzedFiles: readonly AnalyzedFile[],
  options: ProjectAnalysisOptions,
): AnalyzedFile[] {
  const eligibleLanguages = new Set([
    'javascript',
    'typescript',
    'go',
    'java',
    'php',
    'python',
    'ruby',
    'rust',
  ]);
  const projectAnalysisEligibleFiles = analyzedFiles.filter((file) =>
    eligibleLanguages.has(file.language),
  );
  const contexts = createFileContexts(projectAnalysisEligibleFiles);

  emitMissingAuthorizationFacts(contexts);
  emitMissingOwnershipFacts(contexts);
  emitFrontendOnlyAuthorizationFacts(contexts);
  emitRepeatedIoFacts(contexts);
  emitMissingBatchFacts(contexts);
  emitNPlusOneAwaitInMapFacts(contexts);
  emitRedundantNetworkFetchFacts(contexts);
  emitUnstableCacheKeyFacts(contexts);
  emitDuplicateCodeFacts(contexts);
  emitTightCouplingFacts(contexts);
  emitWidePublicSurfaceFacts(contexts);
  emitBarrelCycleFacts(contexts);
  emitDeadExportFacts(contexts);
  emitMissingNextErrorBoundaryFacts(contexts);
  emitMissingTestsFacts(contexts, options.availableTestPaths);
  emitProductionTestBoundaryFacts(contexts);

  if (options.scopeMode === 'diff') {
    emitLogicChangeWithoutTestsFacts(
      contexts,
      options.availableChangedTestPaths,
    );
    emitMissingEdgeCaseTestsFacts(
      contexts,
      options.availableChangedTestPaths,
    );
  }

  appendDependencyFacts(analyzedFiles, options.dependencyFacts ?? []);

  return [...analyzedFiles];
}
