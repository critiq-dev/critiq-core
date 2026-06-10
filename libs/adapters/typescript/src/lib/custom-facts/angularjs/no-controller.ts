import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { FACT_KINDS } from './constants';

function isControllerCall(node: TSESTree.CallExpression): boolean {
  if (node.callee.type !== 'MemberExpression' || node.callee.computed) {
    return false;
  }

  if (node.callee.property.type !== 'Identifier' || node.callee.property.name !== 'controller') {
    return false;
  }

  if (node.callee.object.type === 'CallExpression') {
    return true;
  }

  if (
    node.callee.object.type === 'Identifier' &&
    node.callee.object.name === 'angular' &&
    node.arguments.length >= 2 &&
    (node.arguments[0].type === 'Literal' || node.arguments[0].type === 'TemplateLiteral')
  ) {
    return true;
  }

  return false;
}

export function collectNoControllerFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (!isControllerCall(node)) {
      return;
    }

    const nameNode =
      node.callee.type === 'MemberExpression'
        ? node.callee.property
        : node.callee;

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.NO_CONTROLLER,
        node: nameNode,
        nodeIds: context.nodeIds,
        props: {
          callee: getNodeText(node.callee, context.sourceText),
        },
        text: getNodeText(node, context.sourceText),
      }),
    );
  });

  return facts;
}
