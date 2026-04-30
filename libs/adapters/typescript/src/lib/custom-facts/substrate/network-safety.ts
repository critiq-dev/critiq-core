import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getCalleeText } from '../shared';

const safeUrlWrapperNames = new Set([
  'allowlistedUrl',
  'assertAllowedHost',
  'assertAllowedUrl',
  'ensureAllowedUrl',
  'normalizeAllowedUrl',
  'normalizeRedirectTarget',
  'safeUrl',
  'validateAllowedUrl',
  'validateUrl',
]);

const safeRedirectWrapperNames = new Set([
  'allowlistedOrigin',
  'assertAllowedOrigin',
  'ensureInternalPath',
  'normalizeRedirectPath',
  'safeRedirectPath',
  'sanitizeRedirectTarget',
  'toInternalPath',
  'validateRedirectTarget',
]);

export function isSafeUrlWrapperName(
  calleeText: string | undefined,
): boolean {
  return Boolean(calleeText && safeUrlWrapperNames.has(calleeText));
}

export function isSafeRedirectWrapperName(
  calleeText: string | undefined,
): boolean {
  return Boolean(calleeText && safeRedirectWrapperNames.has(calleeText));
}

export function isSafeUrlWrapperCall(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): boolean {
  if (!node || node.type !== 'CallExpression') {
    return false;
  }

  return isSafeUrlWrapperName(getCalleeText(node.callee, sourceText));
}

export function isSafeRedirectWrapperCall(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): boolean {
  if (!node || node.type !== 'CallExpression') {
    return false;
  }

  return isSafeRedirectWrapperName(getCalleeText(node.callee, sourceText));
}
