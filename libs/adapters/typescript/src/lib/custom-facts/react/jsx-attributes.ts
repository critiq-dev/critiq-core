import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNumericLiteralValue } from '../shared';

/** Returns the raw JSX attribute entry when present. */
export function getJsxAttribute(
  opening: TSESTree.JSXOpeningElement,
  attrName: string,
): TSESTree.JSXAttribute | undefined {
  for (const attr of opening.attributes) {
    if (
      attr.type === 'JSXAttribute' &&
      attr.name.type === 'JSXIdentifier' &&
      attr.name.name === attrName
    ) {
      return attr;
    }
  }

  return undefined;
}

/** Returns whether the JSX element declares the requested attribute. */
export function hasJsxAttribute(
  opening: TSESTree.JSXOpeningElement,
  attrName: string,
): boolean {
  return Boolean(getJsxAttribute(opening, attrName));
}

/** Reads a JSX string attribute or returns a marker for dynamic expressions. */
export function getJsxStringAttr(
  opening: TSESTree.JSXOpeningElement,
  attrName: string,
): string | undefined {
  const attr = getJsxAttribute(opening, attrName);

  if (!attr) {
    return undefined;
  }

  const value = attr.value;

  if (!value) {
    return '';
  }

  if (value.type === 'Literal' && typeof value.value === 'string') {
    return value.value;
  }

  if (
    value.type === 'JSXExpressionContainer' &&
    value.expression.type === 'Literal' &&
    typeof value.expression.value === 'string'
  ) {
    return value.expression.value;
  }

  return '[expression]';
}

/** Reads a boolean JSX attribute when it is statically encoded. */
export function getJsxBooleanAttr(
  opening: TSESTree.JSXOpeningElement,
  attrName: string,
): boolean | undefined {
  const attr = getJsxAttribute(opening, attrName);

  if (!attr) {
    return undefined;
  }

  if (!attr.value) {
    return true;
  }

  if (attr.value.type === 'Literal') {
    if (typeof attr.value.value === 'boolean') {
      return attr.value.value;
    }

    if (typeof attr.value.value === 'string') {
      if (attr.value.value === 'true') {
        return true;
      }

      if (attr.value.value === 'false') {
        return false;
      }
    }
  }

  if (
    attr.value.type === 'JSXExpressionContainer' &&
    attr.value.expression.type === 'Literal' &&
    typeof attr.value.expression.value === 'boolean'
  ) {
    return attr.value.expression.value;
  }

  return undefined;
}

/** Reads a numeric JSX attribute when it is statically encoded. */
export function getJsxNumericAttr(
  opening: TSESTree.JSXOpeningElement,
  attrName: string,
): number | undefined {
  const attr = getJsxAttribute(opening, attrName);

  if (!attr?.value) {
    return undefined;
  }

  if (attr.value.type === 'Literal') {
    return getNumericLiteralValue(attr.value);
  }

  if (attr.value.type === 'JSXExpressionContainer') {
    if (attr.value.expression.type === 'JSXEmptyExpression') {
      return undefined;
    }

    return getNumericLiteralValue(attr.value.expression);
  }

  return undefined;
}
