import type { TSESTree } from '@typescript-eslint/typescript-estree';

export function unwrapExpression(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.JSXEmptyExpression
    | null
    | undefined,
): TSESTree.Expression | undefined {
  if (!node || node.type === 'JSXEmptyExpression') {
    return undefined;
  }

  if (node.type === 'TSAsExpression' || node.type === 'TSTypeAssertion') {
    return unwrapExpression(node.expression);
  }

  if (node.type === 'ChainExpression') {
    return unwrapExpression(node.expression);
  }

  if (node.type === 'PrivateIdentifier') {
    return undefined;
  }

  return node;
}
