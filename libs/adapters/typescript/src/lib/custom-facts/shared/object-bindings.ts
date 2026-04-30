import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { walkAst } from '../../ast';
import type { TypeScriptFactDetectorContext } from './context';

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

export function getObjectProperty(
  objectExpression: TSESTree.ObjectExpression | null | undefined,
  name: string,
): TSESTree.Property | undefined {
  if (!objectExpression) {
    return undefined;
  }

  return objectExpression.properties.find(
    (property): property is TSESTree.Property =>
      property.type === 'Property' && isPropertyNamed(property.key, name),
  );
}

export function collectObjectBindings(
  context: TypeScriptFactDetectorContext,
): Map<string, TSESTree.ObjectExpression> {
  const bindings = new Map<string, TSESTree.ObjectExpression>();

  walkAst(context.program, (node) => {
    if (node.type !== 'VariableDeclarator') {
      return;
    }

    if (node.id.type !== 'Identifier') {
      return;
    }

    if (!node.init || node.init.type !== 'ObjectExpression') {
      return;
    }

    bindings.set(node.id.name, node.init);
  });

  return bindings;
}

export function resolveObjectExpression(
  expression:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
  bindings: ReadonlyMap<string, TSESTree.ObjectExpression>,
): TSESTree.ObjectExpression | undefined {
  if (!expression || expression.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (expression.type === 'ObjectExpression') {
    return expression;
  }

  if (expression.type === 'Identifier') {
    return bindings.get(expression.name);
  }

  return undefined;
}
