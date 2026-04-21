import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  getStringLiteralValue,
  isBooleanLiteral,
  looksSensitiveIdentifier,
  walkAst,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

export const INSECURE_AUTH_COOKIE_FLAGS_RULE_ID =
  'ts.security.insecure-auth-cookie-flags';
export const JWT_SENSITIVE_CLAIMS_RULE_ID = 'ts.security.jwt-sensitive-claims';
export const BROWSER_TOKEN_STORAGE_RULE_ID =
  'ts.security.browser-token-storage';

const COOKIE_SINKS = new Set([
  'cookies.set',
  'reply.setCookie',
  'res.cookie',
  'serialize',
  'setCookie',
]);

const JWT_SINKS = new Set([
  'createToken',
  'encodeJwt',
  'jwt.encode',
  'jwt.sign',
  'setToken',
  'signJwt',
]);

const STORAGE_SINKS = new Set([
  'localStorage.setItem',
  'sessionStorage.setItem',
  'window.localStorage.setItem',
  'window.sessionStorage.setItem',
]);

const sensitiveClaimKeyPattern =
  /^(address|auth|card|cookie|credit|dob|email|jwt|password|permissions?|phone|role|secret|session|ssn|token)$/i;

const sensitiveStorageKeyPattern =
  /^(access|auth|credential|jwt|refresh|session|token)$/i;

function collectObjectBindings(
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

function resolveObjectExpression(
  expression: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  bindings: Map<string, TSESTree.ObjectExpression>,
): TSESTree.ObjectExpression | undefined {
  if (!expression) {
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

function isSensitiveCookieName(name: string | undefined): boolean {
  return typeof name === 'string' && /^(auth|cookie|jwt|session|token)/i.test(name);
}

function getPropertyNames(objectExpression: TSESTree.ObjectExpression): string[] {
  const names: string[] = [];

  for (const property of objectExpression.properties) {
    if (property.type !== 'Property') {
      continue;
    }

    const key =
      property.key.type === 'Identifier'
        ? property.key.name
        : property.key.type === 'Literal' && typeof property.key.value === 'string'
          ? property.key.value
          : getNodeText(property.key, '');

    if (key) {
      names.push(key);
    }
  }

  return names;
}

function isCookieBooleanFlagSafe(
  options: TSESTree.ObjectExpression | undefined,
  name: string,
): boolean {
  const property = getObjectProperty(options, name);

  if (!property) {
    return false;
  }

  return !isBooleanLiteral(
    property.value as TSESTree.Expression | TSESTree.PrivateIdentifier | undefined,
    false,
  );
}

function hasSafeSameSiteFlag(
  options: TSESTree.ObjectExpression | undefined,
): boolean {
  const sameSiteProperty = getObjectProperty(options, 'sameSite');

  if (!sameSiteProperty) {
    return false;
  }

  const sameSiteValue = getStringLiteralValue(
    sameSiteProperty.value as TSESTree.Expression | undefined,
  );

  return sameSiteValue?.toLowerCase() !== 'none';
}

function detectCookieFacts(
  context: TypeScriptFactDetectorContext,
  bindings: Map<string, TSESTree.ObjectExpression>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !COOKIE_SINKS.has(calleeText)) {
      return;
    }

    const nameText =
      getStringLiteralValue(node.arguments[0] as TSESTree.Expression) ??
      getNodeText(node.arguments[0] as TSESTree.Expression, context.sourceText);
    const valueText = getNodeText(
      node.arguments[1] as TSESTree.Expression,
      context.sourceText,
    );

    if (
      !isSensitiveCookieName(nameText) &&
      !looksSensitiveIdentifier(nameText) &&
      !looksSensitiveIdentifier(valueText)
    ) {
      return;
    }

    const optionsExpression = node.arguments[node.arguments.length - 1] as
      | TSESTree.Expression
      | undefined;
    const options = resolveObjectExpression(optionsExpression, bindings);
    const missingFlags: string[] = [];

    if (!isCookieBooleanFlagSafe(options, 'httpOnly')) {
      missingFlags.push('httpOnly');
    }

    if (!isCookieBooleanFlagSafe(options, 'secure')) {
      missingFlags.push('secure');
    }

    if (!hasSafeSameSiteFlag(options)) {
      missingFlags.push('sameSite');
    }

    if (missingFlags.length === 0) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: INSECURE_AUTH_COOKIE_FLAGS_RULE_ID,
        node,
        nodeIds: context.nodeIds,
        props: {
          cookieName: nameText,
          missingFlags,
        },
        text: calleeText,
      }),
    );
  });

  return facts;
}

function detectJwtFacts(
  context: TypeScriptFactDetectorContext,
  bindings: Map<string, TSESTree.ObjectExpression>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !JWT_SINKS.has(calleeText)) {
      return;
    }

    const payloadExpression = node.arguments[0] as
      | TSESTree.Expression
      | TSESTree.PrivateIdentifier
      | undefined;
    const payloadObject = resolveObjectExpression(
      payloadExpression as TSESTree.Expression | null | undefined,
      bindings,
    );

    if (!payloadObject) {
      return;
    }

    const sensitiveClaims = getPropertyNames(payloadObject).filter((name) =>
      sensitiveClaimKeyPattern.test(name),
    );

    if (sensitiveClaims.length === 0) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: JWT_SENSITIVE_CLAIMS_RULE_ID,
        node,
        nodeIds: context.nodeIds,
        props: {
          sensitiveClaims,
        },
        text: calleeText,
      }),
    );
  });

  return facts;
}

function detectBrowserStorageFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !STORAGE_SINKS.has(calleeText)) {
      return;
    }

    const storageKey =
      getStringLiteralValue(node.arguments[0] as TSESTree.Expression) ??
      getNodeText(node.arguments[0] as TSESTree.Expression, context.sourceText);
    const storageValue = getNodeText(
      node.arguments[1] as TSESTree.Expression,
      context.sourceText,
    );

    if (
      !sensitiveStorageKeyPattern.test(storageKey ?? '') &&
      !/(access|auth|credential|jwt|refresh|session|token)/i.test(
        storageValue ?? '',
      ) &&
      !looksSensitiveIdentifier(storageKey) &&
      !looksSensitiveIdentifier(storageValue)
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: BROWSER_TOKEN_STORAGE_RULE_ID,
        node,
        nodeIds: context.nodeIds,
        props: {
          storageKey,
          storageType: calleeText.includes('sessionStorage')
            ? 'sessionStorage'
            : 'localStorage',
        },
        text: calleeText,
      }),
    );
  });

  return facts;
}

export const collectInsecureCookieJwtSessionFacts: TypeScriptFactDetector = (
  context,
) => {
  const bindings = collectObjectBindings(context);
  const facts = [
    ...detectCookieFacts(context, bindings),
    ...detectJwtFacts(context, bindings),
    ...detectBrowserStorageFacts(context),
  ];

  return facts.sort((left, right) => {
    if (left.range.startLine !== right.range.startLine) {
      return left.range.startLine - right.range.startLine;
    }

    if (left.range.startColumn !== right.range.startColumn) {
      return left.range.startColumn - right.range.startColumn;
    }

    return left.kind.localeCompare(right.kind);
  });
};
