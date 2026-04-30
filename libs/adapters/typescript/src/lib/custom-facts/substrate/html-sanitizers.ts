import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getCalleeText } from '../shared';

export const trustedHtmlSanitizerCalleeNames = new Set([
  '_.escape',
  'DOMPurify.sanitize',
  'he.escape',
  'lodash.escape',
  'validator.escape',
]);

export const trustedHtmlSanitizerLeafNames = new Set([
  'escapeHTML',
  'escapeHtml',
  'sanitize',
  'sanitizeHTML',
  'sanitizeHtml',
]);

export function getLeafCalleeName(
  calleeText: string | undefined,
): string | undefined {
  if (!calleeText) {
    return undefined;
  }

  return calleeText
    .split('.')
    .at(-1)
    ?.replace(/\?$/u, '')
    .replace(/^#/u, '');
}

export function isTrustedHtmlSanitizerName(
  calleeText: string | undefined,
): boolean {
  const leafName = getLeafCalleeName(calleeText);

  if (calleeText && trustedHtmlSanitizerCalleeNames.has(calleeText)) {
    return true;
  }

  return Boolean(
    leafName &&
      (trustedHtmlSanitizerLeafNames.has(leafName) ||
        /^sanitize[A-Za-z0-9_$]*$/u.test(leafName)),
  );
}

export function isTrustedHtmlSanitizerCall(
  expression: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  return isTrustedHtmlSanitizerName(
    getCalleeText(expression.callee, sourceText),
  );
}
