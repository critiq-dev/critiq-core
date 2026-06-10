import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { walkAst } from '../shared';

const ANGULAR_MODULE_METHODS = new Set([
  'module',
  'controller',
  'directive',
  'service',
  'factory',
  'provider',
  'config',
  'run',
  'filter',
  'decorator',
  'component',
  'animation',
  'value',
  'constant',
]);

const ANGULAR_MOCK_METHODS = new Set([
  'inject',
  'module',
]);

function isAngularModuleCall(node: TSESTree.CallExpression): boolean {
  if (node.callee.type !== 'MemberExpression' || node.callee.computed) {
    return false;
  }

  if (node.callee.property.type !== 'Identifier') {
    return false;
  }

  if (!ANGULAR_MODULE_METHODS.has(node.callee.property.name)) {
    return false;
  }

  let current: TSESTree.Node = node.callee.object;

  while (current.type === 'CallExpression') {
    if (current.callee.type !== 'MemberExpression') {
      return false;
    }

    current = current.callee.object;
  }

  return current.type === 'Identifier' && current.name === 'angular';
}

export function hasAngularJsContext(program: TSESTree.Program): boolean {
  let found = false;

  walkAst(program, (node) => {
    if (found) {
      return;
    }

    if (node.type !== 'CallExpression') {
      return;
    }

    if (isAngularModuleCall(node)) {
      found = true;
      return;
    }

    if (
      node.callee.type === 'MemberExpression' &&
      !node.callee.computed &&
      node.callee.object.type === 'MemberExpression' &&
      !node.callee.object.computed &&
      node.callee.object.object.type === 'Identifier' &&
      node.callee.object.object.name === 'angular' &&
      node.callee.object.property.type === 'Identifier' &&
      node.callee.object.property.name === 'mock' &&
      node.callee.property.type === 'Identifier' &&
      ANGULAR_MOCK_METHODS.has(node.callee.property.name)
    ) {
      found = true;
    }
  });

  return found;
}
