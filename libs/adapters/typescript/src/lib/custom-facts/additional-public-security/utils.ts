import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  getNumericLiteralValue,
  getObjectProperty,
  getStringLiteralValue,
  normalizeText as normalizeSharedText,
} from '../shared';

export function getLiteralString(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
): string | undefined {
  return getStringLiteralValue(
    node as
      | TSESTree.Expression
      | TSESTree.PrivateIdentifier
      | TSESTree.CallExpressionArgument
      | null
      | undefined,
  );
}

export function getLiteralNumber(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
): number | undefined {
  return getNumericLiteralValue(
    node as
      | TSESTree.Expression
      | TSESTree.PrivateIdentifier
      | TSESTree.CallExpressionArgument
      | null
      | undefined,
  );
}

export function normalizeText(text: string | undefined): string {
  return normalizeSharedText(text);
}

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

export function objectPropertyNames(
  objectExpression: TSESTree.ObjectExpression,
): Set<string> {
  const names = new Set<string>();

  for (const property of objectExpression.properties) {
    if (property.type !== 'Property') {
      continue;
    }

    const key =
      property.key.type === 'Identifier'
        ? property.key.name
        : property.key.type === 'Literal' &&
            typeof property.key.value === 'string'
          ? property.key.value
          : undefined;

    if (key) {
      names.add(key);
    }
  }

  return names;
}

export function objectBooleanFlagFalse(
  objectExpression: TSESTree.ObjectExpression | undefined,
  name: string,
): boolean {
  const property = getObjectProperty(objectExpression, name);

  return property?.value.type === 'Literal' && property.value.value === false;
}

export function isHtmlLikeText(text: string | undefined): boolean {
  return typeof text === 'string' && /<\w+(\s[^>]*)?>/u.test(text);
}
