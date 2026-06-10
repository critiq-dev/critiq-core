import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { FACT_KINDS } from './constants';
import { hasAngularJsContext } from './angularjs-context';

function isTypeofStringCheck(node: TSESTree.BinaryExpression): boolean {
  if (
    node.operator !== '===' &&
    node.operator !== '!==' &&
    node.operator !== '==' &&
    node.operator !== '!='
  ) {
    return false;
  }

  const typeofSide =
    node.left.type === 'UnaryExpression' &&
    node.left.operator === 'typeof'
      ? node.left
      : node.right.type === 'UnaryExpression' && node.right.operator === 'typeof'
        ? node.right
        : null;

  if (!typeofSide) {
    return false;
  }

  const literalSide = typeofSide === node.left ? node.right : node.left;

  return (
    literalSide.type === 'Literal' &&
    literalSide.value === 'string'
  );
}

export function collectPreferAngularIsStringFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  if (!hasAngularJsContext(context.program)) {
    return [];
  }

  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'BinaryExpression') {
      return;
    }

    if (!isTypeofStringCheck(node)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.PREFER_ANGULAR_IS_STRING,
        node,
        nodeIds: context.nodeIds,
        props: {
          operator: node.operator,
        },
        text: getNodeText(node, context.sourceText),
      }),
    );
  });

  return facts;
}
