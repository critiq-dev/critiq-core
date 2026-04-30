import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

export interface TypeScriptFactDetectorContext {
  nodeIds: WeakMap<object, string>;
  path: string;
  program: TSESTree.Program;
  sourceText: string;
}

export interface CreateObservedFactOptions {
  appliesTo: ObservedFact['appliesTo'];
  kind: string;
  node: TSESTree.Node;
  nodeIds: WeakMap<object, string>;
  props?: Record<string, unknown>;
  text?: string;
}

export type TypeScriptFactDetector = (
  context: TypeScriptFactDetectorContext,
) => ObservedFact[];

export type FunctionLikeNode =
  | TSESTree.ArrowFunctionExpression
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression;
