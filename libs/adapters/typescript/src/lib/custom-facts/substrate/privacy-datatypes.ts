import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { collectSensitiveDisclosureLabels } from '../disclosure-signals';

export const sharedPrivacyDatatypes = [
  'email',
  'phone',
  'address',
  'dob',
  'ssn',
  'token',
  'jwt',
  'secret',
  'password',
  'session',
  'cookie',
  'auth',
  'card',
  'billing',
  'profile',
  'support',
] as const;

export type SharedPrivacyDatatype = (typeof sharedPrivacyDatatypes)[number];

export function collectSharedPrivacyDatatypes(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): SharedPrivacyDatatype[] {
  return collectSensitiveDisclosureLabels(node, sourceText, {
    includeStringLiterals: false,
  }) as SharedPrivacyDatatype[];
}
