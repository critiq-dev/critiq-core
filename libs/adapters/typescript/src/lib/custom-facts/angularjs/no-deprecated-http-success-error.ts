import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { FACT_KINDS } from './constants';

function isHttpCall(node: TSESTree.Expression): boolean {
  if (node.type === 'CallExpression') {
    if (node.callee.type === 'Identifier' && node.callee.name === '$http') {
      return true;
    }

    if (
      node.callee.type === 'MemberExpression' &&
      !node.callee.computed &&
      node.callee.object.type === 'Identifier' &&
      node.callee.object.name === '$http'
    ) {
      return true;
    }
  }

  return false;
}

export function collectNoDeprecatedHttpSuccessErrorFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (
      node.callee.type !== 'MemberExpression' ||
      node.callee.computed ||
      node.callee.property.type !== 'Identifier'
    ) {
      return;
    }

    const methodName = node.callee.property.name;

    if (methodName !== 'success' && methodName !== 'error') {
      return;
    }

    if (!isHttpCall(node.callee.object)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.NO_DEPRECATED_HTTP_SUCCESS_ERROR,
        node: node.callee.property,
        nodeIds: context.nodeIds,
        props: {
          symbol: methodName === 'success' ? '.success' : '.error',
        },
        text: getNodeText(node, context.sourceText),
      }),
    );
  });

  return facts;
}
