import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getCalleeText } from '../shared';

const sharedPrivacySafeWrapperNames = new Set([
  'anonymize',
  'dropSensitiveFields',
  'hashSensitiveValue',
  'mask',
  'maskSensitiveData',
  'omitSensitiveFields',
  'redact',
  'redactSensitive',
  'redactSensitiveData',
  'safeSerialize',
  'sanitize',
  'sanitizePayload',
  'stripSensitiveFields',
]);

export const sharedPrivacySafeWrapperPattern =
  /(^|\.)(anonymize|dropSensitiveFields|hashSensitiveValue|mask|maskSensitiveData|omitSensitiveFields|redact|redactSensitive|redactSensitiveData|safeSerialize|sanitize|sanitizePayload|stripSensitiveFields)$/u;

export function isSharedPrivacySafeWrapperName(
  calleeText: string | undefined,
): boolean {
  return Boolean(calleeText && sharedPrivacySafeWrapperNames.has(calleeText));
}

export function isSharedPrivacySafeWrapperCall(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): boolean {
  if (!node || node.type !== 'CallExpression') {
    return false;
  }

  return isSharedPrivacySafeWrapperName(getCalleeText(node.callee, sourceText));
}
