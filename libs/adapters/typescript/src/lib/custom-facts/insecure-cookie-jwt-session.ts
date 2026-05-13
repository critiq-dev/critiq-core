import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  isAuthCookieName,
  isAuthLikeText,
  isAuthStorageKey,
  isSensitiveAuthJwtClaimText,
} from '../auth-vocabulary';
import {
  collectObjectBindings,
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  getStringLiteralValue,
  isBooleanLiteral,
  looksSensitiveIdentifier,
  resolveObjectExpression,
  walkAst,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

export const INSECURE_AUTH_COOKIE_FLAGS_RULE_ID =
  'ts.security.insecure-auth-cookie-flags';
export const JWT_SENSITIVE_CLAIMS_RULE_ID = 'ts.security.jwt-sensitive-claims';
export const JWT_INSECURE_SIGNING_ALGORITHM_RULE_ID =
  'ts.security.jwt-insecure-signing-algorithm';
export const BROWSER_TOKEN_STORAGE_RULE_ID =
  'ts.security.browser-token-storage';

const COOKIE_SINKS = new Set([
  'cookie.serialize',
  'cookies().set',
  'cookies.set',
  'NextResponse.cookies.set',
  'reply.setCookie',
  'reply.cookie',
  'res.cookie',
  'response.cookies.set',
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

function getCookieCallDetails(
  node: TSESTree.CallExpression,
  bindings: Map<string, TSESTree.ObjectExpression>,
  sourceText: string,
): {
  nameText: string | undefined;
  options: TSESTree.ObjectExpression | undefined;
  valueText: string | undefined;
} {
  const firstArgument = node.arguments[0] as TSESTree.Expression | undefined;
  const objectStyleCookie = resolveObjectExpression(firstArgument, bindings);

  if (objectStyleCookie) {
    const nameProperty = getObjectProperty(objectStyleCookie, 'name');
    const valueProperty = getObjectProperty(objectStyleCookie, 'value');

    return {
      nameText:
        getStringLiteralValue(nameProperty?.value as TSESTree.Expression) ??
        getNodeText(nameProperty?.value, sourceText),
      options: objectStyleCookie,
      valueText: getNodeText(valueProperty?.value, sourceText),
    };
  }

  const optionsExpression = node.arguments[node.arguments.length - 1] as
    | TSESTree.Expression
    | undefined;

  return {
    nameText:
      getStringLiteralValue(firstArgument) ?? getNodeText(firstArgument, sourceText),
    options: resolveObjectExpression(optionsExpression, bindings),
    valueText: getNodeText(
      node.arguments[1] as TSESTree.Expression,
      sourceText,
    ),
  };
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

    const { nameText, options, valueText } = getCookieCallDetails(
      node,
      bindings,
      context.sourceText,
    );

    if (
      !isAuthCookieName(nameText) &&
      !isAuthLikeText(nameText) &&
      !isAuthLikeText(valueText) &&
      !looksSensitiveIdentifier(nameText) &&
      !looksSensitiveIdentifier(valueText)
    ) {
      return;
    }

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
      isSensitiveAuthJwtClaimText(name),
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

function algorithmsArrayContainsNone(
  arrayExpression: TSESTree.ArrayExpression | undefined,
): boolean {
  if (!arrayExpression) {
    return false;
  }

  for (const element of arrayExpression.elements) {
    if (element?.type === 'Literal' && element.value === 'none') {
      return true;
    }
  }

  return false;
}

function detectJwtInsecureSigningAlgorithmFacts(
  context: TypeScriptFactDetectorContext,
  bindings: Map<string, TSESTree.ObjectExpression>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText !== 'jwt.sign') {
      return;
    }

    const options = resolveObjectExpression(
      node.arguments[2] as TSESTree.Expression | undefined,
      bindings,
    );

    if (!options) {
      return;
    }

    const algorithmProperty = getObjectProperty(options, 'algorithm');

    if (
      algorithmProperty?.value.type === 'Literal' &&
      algorithmProperty.value.value === 'none'
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: JWT_INSECURE_SIGNING_ALGORITHM_RULE_ID,
          node,
          nodeIds: context.nodeIds,
          text: calleeText,
        }),
      );

      return;
    }

    const algorithmsProperty = getObjectProperty(options, 'algorithms');

    if (
      algorithmsProperty?.value.type === 'ArrayExpression' &&
      algorithmsArrayContainsNone(algorithmsProperty.value)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: JWT_INSECURE_SIGNING_ALGORITHM_RULE_ID,
          node,
          nodeIds: context.nodeIds,
          text: calleeText,
        }),
      );
    }
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
      !isAuthStorageKey(storageKey) &&
      !isAuthLikeText(storageValue) &&
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
    ...detectJwtInsecureSigningAlgorithmFacts(context, bindings),
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
