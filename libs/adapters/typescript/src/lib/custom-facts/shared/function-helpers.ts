import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isNode } from '../../ast';
import type { FunctionLikeNode } from './context';

export function isFunctionLike(
  node: TSESTree.Node | null | undefined,
): node is FunctionLikeNode {
  return Boolean(
    node &&
      (node.type === 'ArrowFunctionExpression' ||
        node.type === 'FunctionDeclaration' ||
        node.type === 'FunctionExpression'),
  );
}

export function walkFunctionBodySkippingNestedFunctions(
  root: FunctionLikeNode,
  visitor: (node: TSESTree.Node) => void,
): void {
  const visit = (node: TSESTree.Node): void => {
    if (isFunctionLike(node) && node !== root) {
      return;
    }

    visitor(node);

    for (const value of Object.values(node)) {
      if (!value) {
        continue;
      }

      if (Array.isArray(value)) {
        for (const entry of value) {
          if (isNode(entry)) {
            visit(entry);
          }
        }

        continue;
      }

      if (isNode(value)) {
        visit(value);
      }
    }
  };

  if (root.body.type === 'BlockStatement') {
    for (const statement of root.body.body) {
      visit(statement);
    }

    return;
  }

  visit(root.body);
}
