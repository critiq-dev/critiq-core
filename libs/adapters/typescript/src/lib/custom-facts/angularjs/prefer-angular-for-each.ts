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

function isAngularForEachCallee(callee: TSESTree.MemberExpression): boolean {
  const object = callee.object;

  return (
    object.type === 'Identifier' &&
    object.name === 'angular' &&
    callee.property.type === 'Identifier' &&
    callee.property.name === 'forEach'
  );
}

function isNativeForEachCallee(callee: TSESTree.MemberExpression): boolean {
  if (callee.computed || callee.property.type !== 'Identifier' || callee.property.name !== 'forEach') {
    return false;
  }

  const object = callee.object;

  return object.type !== 'Identifier' || object.name !== 'angular';
}

export function collectPreferAngularForEachFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  if (!hasAngularJsContext(context.program)) {
    return [];
  }

  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const { callee } = node;

    if (callee.type !== 'MemberExpression' || callee.computed) {
      return;
    }

    if (isAngularForEachCallee(callee)) {
      return;
    }

    if (!isNativeForEachCallee(callee)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.PREFER_ANGULAR_FOR_EACH,
        node: callee.property,
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
