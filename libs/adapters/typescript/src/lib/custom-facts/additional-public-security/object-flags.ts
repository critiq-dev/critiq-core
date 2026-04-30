import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getObjectProperty } from '../shared';
import { getStaticPropertyName } from './property-names';

export function objectPropertyNames(
  objectExpression: TSESTree.ObjectExpression,
): Set<string> {
  const names = new Set<string>();

  for (const property of objectExpression.properties) {
    if (property.type !== 'Property') {
      continue;
    }

    const key = getStaticPropertyName(property.key);

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
