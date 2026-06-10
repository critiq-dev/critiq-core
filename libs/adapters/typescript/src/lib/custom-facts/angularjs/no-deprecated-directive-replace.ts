import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { FACT_KINDS } from './constants';

const DIRECTIVE_KEYS = new Set([
  'template',
  'templateUrl',
  'scope',
  'link',
  'compile',
  'restrict',
  'controller',
  'controllerAs',
  'bindToController',
  'require',
  'transclude',
  'priority',
  'terminal',
  'multiElement',
]);

function isDirectiveDefinitionObject(
  node: TSESTree.ObjectExpression,
): boolean {
  return node.properties.some(
    (prop) =>
      prop.type === 'Property' &&
      !prop.computed &&
      prop.key.type === 'Identifier' &&
      DIRECTIVE_KEYS.has(prop.key.name),
  );
}

function findDirectiveObjectArgs(
  program: TSESTree.Program,
): Set<TSESTree.ObjectExpression> {
  const directiveObjects = new Set<TSESTree.ObjectExpression>();

  walkAst(program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (
      node.callee.type !== 'MemberExpression' ||
      node.callee.computed ||
      node.callee.property.type !== 'Identifier' ||
      node.callee.property.name !== 'directive'
    ) {
      return;
    }

    for (const arg of node.arguments) {
      if (arg.type === 'ObjectExpression' && isDirectiveDefinitionObject(arg)) {
        directiveObjects.add(arg);
      }

      if (
        arg.type === 'ArrowFunctionExpression' ||
        arg.type === 'FunctionExpression'
      ) {
        if (arg.body.type === 'BlockStatement') {
          for (const stmt of arg.body.body) {
            if (
              stmt.type === 'ReturnStatement' &&
              stmt.argument &&
              stmt.argument.type === 'ObjectExpression' &&
              isDirectiveDefinitionObject(stmt.argument)
            ) {
              directiveObjects.add(stmt.argument);
            }
          }
        } else if (
          arg.body.type === 'ObjectExpression' &&
          isDirectiveDefinitionObject(arg.body)
        ) {
          directiveObjects.add(arg.body);
        }
      }
    }
  });

  return directiveObjects;
}

export function collectNoDeprecatedDirectiveReplaceFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const directiveObjects = findDirectiveObjectArgs(context.program);

  for (const obj of directiveObjects) {
    for (const prop of obj.properties) {
      if (
        prop.type === 'Property' &&
        !prop.computed &&
        prop.key.type === 'Identifier' &&
        prop.key.name === 'replace'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.NO_DEPRECATED_DIRECTIVE_REPLACE,
            node: prop.key,
            nodeIds: context.nodeIds,
            props: {
              symbol: 'replace',
            },
            text: getNodeText(prop, context.sourceText),
          }),
        );
      }
    }
  }

  return facts;
}
