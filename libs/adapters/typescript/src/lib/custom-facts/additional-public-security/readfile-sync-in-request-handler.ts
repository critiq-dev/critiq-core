import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  isFunctionLike,
  walkAst,
  walkFunctionBodySkippingNestedFunctions,
  type TypeScriptFactDetectorContext,
} from '../shared';

import { type FunctionLikeNode } from './analysis';
import { FACT_KINDS, fileReadSinkNames } from './constants';

function isLikelyHttpRequestHandler(
  params: readonly TSESTree.Parameter[],
): boolean {
  return params.some(
    (parameter) =>
      parameter.type === 'Identifier' &&
      /^(req|request)$/u.test(parameter.name),
  );
}

function collectReadFileSyncFactsInHandler(
  handler: FunctionLikeNode,
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkFunctionBodySkippingNestedFunctions(handler, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !fileReadSinkNames.has(calleeText)) {
      return;
    }

    if (!calleeText.endsWith('readFileSync')) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.readFileSyncInRequestHandler,
        node,
        nodeIds: context.nodeIds,
        text: calleeText,
      }),
    );
  });

  return facts;
}

/** Blocking `readFileSync` inside HTTP request handlers. */
export function collectReadFileSyncInRequestHandlerFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (!isFunctionLike(node) || !isLikelyHttpRequestHandler(node.params)) {
      return;
    }

    facts.push(
      ...collectReadFileSyncFactsInHandler(node, context),
    );
  });

  return facts;
}
