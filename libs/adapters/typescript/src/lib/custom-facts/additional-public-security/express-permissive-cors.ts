import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  collectObjectBindings,
  createObservedFact,
  getCalleeText,
  getObjectProperty,
  resolveObjectExpression,
  walkAst,
  walkFunctionBodySkippingNestedFunctions,
  type TypeScriptFactDetectorContext,
} from '../shared';

import {
  resolveFunctionBindings,
  resolveFunctionLike,
  type FunctionLikeNode,
} from './analysis';
import { FACT_KINDS } from './constants';
import { objectBooleanFlagTrue } from './object-flags';

function classifyPermissiveOrigin(
  originValue: TSESTree.Expression,
  functionBindings: ReadonlyMap<string, FunctionLikeNode>,
): boolean {
  if (originValue.type === 'Literal') {
    return originValue.value === '*' || originValue.value === true;
  }

  if (
    originValue.type === 'ArrayExpression' &&
    originValue.elements.some(
      (element) =>
        element?.type === 'Literal' &&
        typeof element.value === 'string' &&
        element.value === '*',
    )
  ) {
    return true;
  }

  const callback = resolveFunctionLike(originValue, functionBindings);

  if (!callback) {
    return false;
  }

  const callbackParam =
    callback.params[1]?.type === 'Identifier' ? callback.params[1] : undefined;

  if (!callbackParam) {
    return (
      callback.body.type !== 'BlockStatement' &&
      callback.body.type === 'Literal' &&
      (callback.body.value === true || callback.body.value === '*')
    );
  }

  let allowsAllOrigins = false;

  walkFunctionBodySkippingNestedFunctions(callback, (node) => {
    if (
      allowsAllOrigins ||
      node.type !== 'CallExpression' ||
      node.callee.type !== 'Identifier' ||
      node.callee.name !== callbackParam.name
    ) {
      return;
    }

    const decisionArgument =
      node.arguments[1] && node.arguments[1].type !== 'SpreadElement'
        ? node.arguments[1]
        : undefined;

    if (
      decisionArgument?.type === 'Literal' &&
      (decisionArgument.value === true || decisionArgument.value === '*')
    ) {
      allowsAllOrigins = true;
    }
  });

  return allowsAllOrigins;
}

function corsConfigIsPermissiveWithCredentials(
  config: TSESTree.ObjectExpression | undefined,
  functionBindings: ReadonlyMap<string, FunctionLikeNode>,
): boolean {
  if (!config || !objectBooleanFlagTrue(config, 'credentials')) {
    return false;
  }

  const originProperty = getObjectProperty(config, 'origin');

  if (!originProperty) {
    return true;
  }

  return classifyPermissiveOrigin(
    originProperty.value as TSESTree.Expression,
    functionBindings,
  );
}

/** `cors()` configs that reflect any origin while sending credentials. */
export function collectExpressPermissiveCorsFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const objectBindings = collectObjectBindings(context);
  const functionBindings = resolveFunctionBindings(context);

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (getCalleeText(node.callee, context.sourceText) !== 'cors') {
      return;
    }

    const firstArgument =
      node.arguments[0] && node.arguments[0].type !== 'SpreadElement'
        ? node.arguments[0]
        : undefined;

    if (!firstArgument) {
      return;
    }

    const config = resolveObjectExpression(firstArgument, objectBindings);

    if (!corsConfigIsPermissiveWithCredentials(config, functionBindings)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.expressPermissiveCors,
        node,
        nodeIds: context.nodeIds,
        text: 'cors',
      }),
    );
  });

  return facts;
}
