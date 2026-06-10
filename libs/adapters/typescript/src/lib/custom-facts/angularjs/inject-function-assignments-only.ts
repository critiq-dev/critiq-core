import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  isFunctionLike,
  walkAst,
  walkFunctionBodySkippingNestedFunctions,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { FACT_KINDS } from './constants';
import { hasAngularJsContext } from './angularjs-context';

function isInjectCallExpression(node: TSESTree.CallExpression): boolean {
  if (node.callee.type === 'Identifier' && node.callee.name === 'inject') {
    return true;
  }

  if (
    node.callee.type === 'MemberExpression' &&
    !node.callee.computed &&
    node.callee.object.type === 'MemberExpression' &&
    !node.callee.object.computed &&
    node.callee.object.property.type === 'Identifier' &&
    node.callee.object.property.name === 'mock' &&
    node.callee.object.object.type === 'Identifier' &&
    node.callee.object.object.name === 'angular' &&
    node.callee.property.type === 'Identifier' &&
    node.callee.property.name === 'inject'
  ) {
    return true;
  }

  return false;
}

function findInjectCallbacks(
  program: TSESTree.Program,
): TSESTree.FunctionLike[] {
  const callbacks: TSESTree.FunctionLike[] = [];

  walkAst(program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (!isInjectCallExpression(node)) {
      return;
    }

    for (const arg of node.arguments) {
      if (isFunctionLike(arg)) {
        callbacks.push(arg);
      }
    }
  });

  return callbacks;
}

export function collectInjectFunctionAssignmentsOnlyFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  if (!hasAngularJsContext(context.program)) {
    return [];
  }

  const facts: ObservedFact[] = [];
  const callbacks = findInjectCallbacks(context.program);

  for (const cb of callbacks) {
    if (!cb.body || cb.body.type !== 'BlockStatement') {
      continue;
    }

    for (const stmt of cb.body.body) {
      if (
        stmt.type === 'VariableDeclaration' ||
        stmt.type === 'ExpressionStatement'
      ) {
        continue;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.INJECT_FUNCTION_ASSIGNMENTS_ONLY,
          node: stmt,
          nodeIds: context.nodeIds,
          props: {
            statementType: stmt.type,
          },
          text: getNodeText(stmt, context.sourceText),
        }),
      );
    }
  }

  return facts;
}
