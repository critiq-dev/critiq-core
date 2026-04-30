import type {
  ObservedBasicBlock,
  ObservedControlFlowEdge,
  ObservedFact,
  ObservedFunction,
} from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import type { TrustBoundaryValidationState } from '../trust-boundary';

export type FunctionContainerNode =
  | TSESTree.Program
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression
  | TSESTree.ArrowFunctionExpression;

export type FlowNode = TSESTree.Node;
export type ComparisonOperator = '==' | '===' | '!=' | '!==';
export type PrimitiveValue = string | number | boolean | bigint | null;
export type UnreachableReason = 'after-return' | 'after-throw';
export type LoopUpdateDirection = 'increment' | 'decrement';

export interface SequenceResult {
  nextBlockIds: string[];
  terminalReasons: Set<UnreachableReason>;
}

export interface LoopFrame {
  breakBlockIds: string[];
  continueTargetBlockId: string;
}

export interface SwitchFrame {
  breakBlockIds: string[];
}

export interface TraversalState {
  loopFrames: LoopFrame[];
  switchFrames: SwitchFrame[];
}

export interface BuildContext {
  asyncFunctionBindings: Set<string>;
  blocks: ObservedBasicBlock[];
  edges: ObservedControlFlowEdge[];
  facts: ObservedFact[];
  functionIndex: number;
  functions: ObservedFunction[];
  nodeIds: WeakMap<object, string>;
  parentNodes: WeakMap<object, TSESTree.Node | undefined>;
  sourceText: string;
}

export interface FunctionBuildContext {
  blockIndex: number;
  edgeIndex: number;
  functionObservation: ObservedFunction;
  hasReachableValueReturn: boolean;
  root: BuildContext;
}

export interface StaticPrimitiveResult {
  known: true;
  value: PrimitiveValue;
}

export interface ConstantConditionResult {
  value: boolean;
  reason: 'literal-boolean' | 'literal-comparison' | 'negated-literal';
}

export interface LiteralComparisonPattern {
  literalKey: string;
  literalText: string;
  operator: ComparisonOperator;
  subjectText: string;
}

export interface ForLoopInitializerPattern {
  collectionText?: string;
  initialValue?: number;
  kind: 'length-minus-one' | 'number';
  variableName: string;
}

export interface PromiseChainState {
  hasCatch: boolean;
  hasFinally: boolean;
  hasThen: boolean;
  hasThenRejectionHandler: boolean;
}

export interface AwaitSequenceCandidate {
  bindingNames: string[];
  callExpression: TSESTree.CallExpression;
  statement: TSESTree.Statement;
}

export interface StructuralFunctionMetrics {
  cyclomaticComplexity: number;
  maxLoopNestingDepth: number;
  maxNestingDepth: number;
  statementCount: number;
}

export interface StatementSurfaceCandidate {
  key: string;
  node: TSESTree.Node;
  text: string;
}

export interface TopLevelConfigLiteral {
  name: string;
  node: TSESTree.Node;
  valueText: string;
}

export interface BindingFlowState {
  externalInput: boolean;
  maybeNull: boolean;
  optional: boolean;
  tokenLike: boolean;
}

export interface FunctionDataFlowState {
  bindings: Map<string, BindingFlowState>;
  validatedTrustBoundaries: TrustBoundaryValidationState;
  tokenValidatedIdentifiers: Set<string>;
}

export const recognizedErrorSinkCallees = new Set([
  'captureException',
  'console.error',
  'console.warn',
  'logger.error',
  'logger.warn',
]);

export const recognizedAsyncCallees = new Set([
  'fetch',
  'Promise.all',
  'Promise.allSettled',
  'Promise.any',
  'Promise.race',
]);

export const recognizedBlockingSyncCallees = new Set([
  'execFileSync',
  'execSync',
  'fs.appendFileSync',
  'fs.copyFileSync',
  'fs.existsSync',
  'fs.mkdirSync',
  'fs.openSync',
  'fs.readFileSync',
  'fs.readdirSync',
  'fs.realpathSync',
  'fs.rmSync',
  'fs.statSync',
  'fs.unlinkSync',
  'fs.writeFileSync',
  'spawnSync',
]);

export const recognizedExpensiveComputationCallees = new Set([
  'Array.from',
  'JSON.parse',
  'JSON.stringify',
  'Object.entries',
  'Object.keys',
  'Object.values',
]);

export const recognizedExpensiveConstructorCallees = new Set([
  'Intl.DateTimeFormat',
  'Intl.NumberFormat',
  'RegExp',
]);

export const largePayloadExtensionPattern = /\.(csv|jsonl|ndjson|log|parquet|tsv|xml)$/i;
export const suggestiveLargePayloadNamePattern =
  /(archive|buffer|csv|dump|export|jsonl|log|ndjson|payload|report|stream|tsv)/i;
export const trivialMagicNumbers = new Set([-1, 0, 1, 2]);
export const configNameTokens = new Set([
  'api',
  'base',
  'bucket',
  'domain',
  'endpoint',
  'env',
  'environment',
  'feature',
  'flag',
  'host',
  'origin',
  'path',
  'port',
  'queue',
  'region',
  'retry',
  'service',
  'settings',
  'timeout',
  'topic',
  'ttl',
  'uri',
  'url',
]);
export const dictionaryLikeCollectionTokens = new Set([
  'cache',
  'dict',
  'dictionary',
  'index',
  'lookup',
  'map',
  'record',
  'registry',
  'store',
  'table',
]);
export const functionStatementThreshold = 18;
export const functionComplexityThreshold = 10;
export const deepNestingThreshold = 4;
export const nestedLoopThreshold = 2;
export const optionalReturningMethodNames = new Set([
  'find',
  'get',
  'match',
]);
export const tokenRiskyCalleePattern =
  /(^|\.)(decode|deserialize|findSession|getSession|getUserFromToken|loadSession|lookupSession|parseJwt|readSession)$/;
export const tokenValidationCalleePattern =
  /(^|\.)(assertAuthenticated|authenticate|checkSession|checkToken|validateSession|validateToken|verify|verifySession|verifyToken)$/;
