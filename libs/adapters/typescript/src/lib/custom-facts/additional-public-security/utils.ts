import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getObjectProperty } from '../shared';

export function getLiteralString(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
): string | undefined {
  if (!node || node.type !== 'Literal' || typeof node.value !== 'string') {
    return undefined;
  }

  return node.value;
}

export function getLiteralNumber(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
): number | undefined {
  if (!node) {
    return undefined;
  }

  if (node.type === 'Literal' && typeof node.value === 'number') {
    return node.value;
  }

  if (node.type === 'Literal' && typeof node.value === 'string') {
    const literal = node.value.trim();

    if (/^0o[0-7]+$/iu.test(literal)) {
      return Number.parseInt(literal.slice(2), 8);
    }

    if (/^0[0-7]+$/u.test(literal)) {
      return Number.parseInt(literal, 8);
    }
  }

  return undefined;
}

export function normalizeText(text: string | undefined): string {
  return text?.replace(/\s+/gu, ' ').trim() ?? '';
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
