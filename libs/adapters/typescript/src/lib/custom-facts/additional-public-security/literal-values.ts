import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNumericLiteralValue, getStringLiteralValue } from '../shared';

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
