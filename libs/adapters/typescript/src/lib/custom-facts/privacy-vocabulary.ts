import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { collectSensitiveDisclosureLabels } from './disclosure-signals';

export const normalizedPrivacyDatatypes = [
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

export type PrivacyDatatype = (typeof normalizedPrivacyDatatypes)[number];

export function collectPrivacyDatatypes(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): PrivacyDatatype[] {
  return collectSensitiveDisclosureLabels(node, sourceText, {
    includeStringLiterals: false,
  }) as PrivacyDatatype[];
}
