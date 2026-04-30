import type { TSESTree } from '@typescript-eslint/typescript-estree';

export function getStaticPropertyName(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
): string | undefined {
  if (!node) {
    return undefined;
  }

  if (node.type === 'Identifier') {
    return node.name;
  }

  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }

  return undefined;
}

export function getMemberPropertyName(
  memberExpression: TSESTree.MemberExpression,
): string | undefined {
  if (memberExpression.computed) {
    return getStaticPropertyName(memberExpression.property);
  }

  return memberExpression.property.type === 'Identifier'
    ? memberExpression.property.name
    : getStaticPropertyName(memberExpression.property);
}
