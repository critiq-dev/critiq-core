export type {
  ProjectAnalysisOptions,
  ProjectAnalysisScopeMode,
} from './project-analysis/context';
export { isTestPath } from './project-analysis/context';
export {
  collectProjectDependencyFacts,
  isDependencyManifestPath,
  type DependencyManifestInput,
  type ProjectDependencyFact,
} from './project-analysis/dependencies';
export { augmentProjectFacts } from './project-analysis/runtime';
