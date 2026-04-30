import type { TSESTree } from '@typescript-eslint/typescript-estree';

export * from '../../ast';
export * from './compatibility-markers';
export * from './context';
export * from './function-helpers';
export * from './object-bindings';
export * from './observed-facts';

export function isBooleanLiteral(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  value: boolean,
): boolean {
  return node?.type === 'Literal' && node.value === value;
}

export function isIdentifierNamed(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  name: string,
): boolean {
  return node?.type === 'Identifier' && node.name === name;
}

export function isPropertyNamed(
  property:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.Property['key']
    | null
    | undefined,
  name: string,
): boolean {
  if (!property) {
    return false;
  }

  if (property.type === 'Identifier') {
    return property.name === name;
  }

  return property.type === 'Literal' && property.value === name;
}
