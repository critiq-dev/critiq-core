import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getCalleeText } from './shared';

const privacySafeWrapperNames = new Set([
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

export const privacySafeWrapperPattern =
  /(^|\.)(anonymize|dropSensitiveFields|hashSensitiveValue|mask|maskSensitiveData|omitSensitiveFields|redact|redactSensitive|redactSensitiveData|safeSerialize|sanitize|sanitizePayload|stripSensitiveFields)$/u;

export function isPrivacySafeWrapperName(
  calleeText: string | undefined,
): boolean {
  return Boolean(calleeText && privacySafeWrapperNames.has(calleeText));
}

export function isPrivacySafeWrapperCall(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): boolean {
  if (!node || node.type !== 'CallExpression') {
    return false;
  }

  return isPrivacySafeWrapperName(getCalleeText(node.callee, sourceText));
}
