import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isAuthSecretPropertyName } from '../../auth-vocabulary';
import {
  collectObjectBindings,
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  resolveObjectExpression,
  walkAst,
  walkFunctionBodySkippingNestedFunctions,
  type TypeScriptFactDetectorContext,
} from '../shared';
import {
  isRequestDerivedExpression,
  isValidatedTrustBoundaryExpression,
  resolveFunctionLike,
  type FunctionLikeNode,
  type TrustBoundaryValidationState,
} from './analysis';
import {
  FACT_KINDS,
  renderSinkNames,
  sessionCallNames,
  strategyNames,
} from './constants';
import {
  getLiteralString,
} from './literal-values';
import {
  objectBooleanFlagFalse,
  objectPropertyNames,
} from './object-flags';
import { normalizeText } from './text-normalization';

function getTemplateLiteralString(
  node: TSESTree.TemplateLiteral,
): string | undefined {
  if (node.expressions.length > 0) {
    return undefined;
  }

  return node.quasis.map((quasi) => quasi.value.cooked ?? '').join('');
}

function extractInlineSecretText(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string | undefined {
  if (!node || node.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }

  if (node.type === 'TemplateLiteral') {
    return getTemplateLiteralString(node);
  }

  if (node.type !== 'CallExpression') {
    return undefined;
  }

  const calleeText = getCalleeText(node.callee, sourceText);
  const firstArgument = node.arguments[0];

  if (!firstArgument || firstArgument.type === 'SpreadElement') {
    return undefined;
  }

  if (calleeText === 'Buffer.from') {
    return extractInlineSecretText(firstArgument, sourceText);
  }

  if (
    calleeText?.endsWith('.encode') &&
    getNodeText(node.callee, sourceText)?.includes('TextEncoder')
  ) {
    return extractInlineSecretText(firstArgument, sourceText);
  }

  return undefined;
}

function hasInlineSecretExpression(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): boolean {
  const secretValue = extractInlineSecretText(node, sourceText);

  return typeof secretValue === 'string' && secretValue.length >= 8;
}

function findAuthSecretProperty(
  config: TSESTree.ObjectExpression,
  sourceText: string,
): string | undefined {
  for (const property of config.properties) {
    if (property.type !== 'Property') {
      continue;
    }

    const propertyName = getNodeText(property.key, sourceText);

    if (!isAuthSecretPropertyName(propertyName)) {
      continue;
    }

    if (property.value.type === 'ArrayExpression') {
      const hasInlineSecret = property.value.elements.some((element) => {
        if (!element || element.type === 'SpreadElement') {
          return false;
        }

        return hasInlineSecretExpression(element, sourceText);
      });

      if (hasInlineSecret) {
        return propertyName;
      }

      continue;
    }

    if (
      hasInlineSecretExpression(
        property.value as TSESTree.Expression | TSESTree.PrivateIdentifier,
        sourceText,
      )
    ) {
      return propertyName;
    }
  }

  return undefined;
}

function getReturnedCallExpression(
  handler: FunctionLikeNode | undefined,
): TSESTree.CallExpression | undefined {
  if (!handler) {
    return undefined;
  }

  if (handler.body.type !== 'BlockStatement') {
    return handler.body.type === 'CallExpression' ? handler.body : undefined;
  }

  let returnedCall: TSESTree.CallExpression | undefined;

  walkFunctionBodySkippingNestedFunctions(handler, (node) => {
    if (
      returnedCall ||
      node.type !== 'ReturnStatement' ||
      !node.argument ||
      node.argument.type !== 'CallExpression'
    ) {
      return;
    }

    returnedCall = node.argument;
  });

  return returnedCall;
}

function resolveMiddlewareCallExpression(
  expression:
    | TSESTree.Expression
    | TSESTree.SpreadElement
    | TSESTree.PrivateIdentifier
    | undefined,
  functionBindings: ReadonlyMap<string, FunctionLikeNode>,
): TSESTree.CallExpression | undefined {
  if (
    !expression ||
    expression.type === 'SpreadElement' ||
    expression.type === 'PrivateIdentifier' ||
    expression.type !== 'CallExpression'
  ) {
    return undefined;
  }

  const wrapper =
    expression.callee.type === 'Identifier'
      ? resolveFunctionLike(expression.callee, functionBindings)
      : undefined;

  return getReturnedCallExpression(wrapper) ?? expression;
}

function getSessionCookieConfig(
  calleeText: string,
  config: TSESTree.ObjectExpression,
  objectBindings: ReadonlyMap<string, TSESTree.ObjectExpression>,
): TSESTree.ObjectExpression | undefined {
  if (calleeText === 'session') {
    const cookieProperty = getObjectProperty(config, 'cookie');

    return resolveObjectExpression(
      cookieProperty?.value as TSESTree.Expression | undefined,
      objectBindings,
    );
  }

  return config;
}

function hasExplicitCookieAttributes(
  cookieConfig: TSESTree.ObjectExpression,
): boolean {
  const cookiePropertyNames = objectPropertyNames(cookieConfig);

  return (
    cookiePropertyNames.has('name') &&
    (cookiePropertyNames.has('maxAge') || cookiePropertyNames.has('expires')) &&
    cookiePropertyNames.has('path') &&
    cookiePropertyNames.has('domain') &&
    cookiePropertyNames.has('secure') &&
    cookiePropertyNames.has('httpOnly')
  );
}

function getPermissiveCookieReasons(
  cookieConfig: TSESTree.ObjectExpression,
): string[] {
  const reasons: string[] = [];
  const sameSiteValue = getLiteralString(
    getObjectProperty(cookieConfig, 'sameSite')?.value as
      | TSESTree.Expression
      | undefined,
  )?.toLowerCase();
  const domainValue = getLiteralString(
    getObjectProperty(cookieConfig, 'domain')?.value as
      | TSESTree.Expression
      | undefined,
  );

  if (sameSiteValue === 'none') {
    reasons.push('sameSite');
  }

  if (domainValue && (domainValue.includes('*') || domainValue.startsWith('.'))) {
    reasons.push('domain');
  }

  return reasons;
}

export function collectHardcodedAuthSecretFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const objectBindings = collectObjectBindings(context);

  walkAst(context.program, (node) => {
    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);
      const configArgument = node.arguments[0];
      const firstArgument =
        configArgument && configArgument.type !== 'SpreadElement'
          ? configArgument
          : undefined;
      const secondArgument =
        node.arguments[1] && node.arguments[1].type !== 'SpreadElement'
          ? node.arguments[1]
          : undefined;

      if (
        calleeText === 'jwt.sign' &&
        hasInlineSecretExpression(
          secondArgument as TSESTree.Expression | undefined,
          context.sourceText,
        )
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.hardcodedAuthSecret,
            node,
            nodeIds: context.nodeIds,
            props: {
              sink: calleeText,
              secretProperty: 'secret',
            },
            text: calleeText,
          }),
        );
      }

      if (
        calleeText?.endsWith('.sign') &&
        normalizeText(calleeText).includes('SignJWT') &&
        hasInlineSecretExpression(
          firstArgument as TSESTree.Expression | undefined,
          context.sourceText,
        )
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.hardcodedAuthSecret,
            node,
            nodeIds: context.nodeIds,
            props: {
              sink: calleeText,
              secretProperty: 'secret',
            },
            text: calleeText,
          }),
        );
      }

      if (
        (calleeText === 'cookieSession' ||
          calleeText === 'session' ||
          calleeText === 'expressjwt' ||
          calleeText === 'expressJwt') &&
        configArgument &&
        configArgument.type !== 'SpreadElement'
      ) {
        const config = resolveObjectExpression(configArgument, objectBindings);
        const secretProperty = config
          ? findAuthSecretProperty(config, context.sourceText)
          : undefined;

        if (secretProperty) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.hardcodedAuthSecret,
              node,
              nodeIds: context.nodeIds,
              props: {
                sink: calleeText,
                secretProperty,
              },
              text: calleeText,
            }),
          );
        }
      }

      return;
    }

    if (node.type !== 'NewExpression' || node.callee.type !== 'Identifier') {
      return;
    }

    if (!strategyNames.has(node.callee.name)) {
      return;
    }

    const config = resolveObjectExpression(node.arguments[0], objectBindings);

    if (!config) {
      return;
    }

    const secretProperty = findAuthSecretProperty(config, context.sourceText);

    if (secretProperty) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.hardcodedAuthSecret,
          node,
          nodeIds: context.nodeIds,
          props: {
            sink: node.callee.name,
            secretProperty,
          },
          text: node.callee.name,
        }),
      );
    }
  });

  return facts;
}

export function collectDatadogBrowserFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText !== 'DD_RUM.init' && calleeText !== 'window.DD_RUM.init') {
      return;
    }

    const config = node.arguments[0];

    if (
      !config ||
      config.type === 'SpreadElement' ||
      config.type !== 'ObjectExpression'
    ) {
      return;
    }

    const trackProperty = getObjectProperty(config, 'trackUserInteractions');

    if (
      trackProperty?.value.type !== 'Literal' ||
      trackProperty.value.value !== true
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.datadogBrowserTrackUserInteractions,
        node,
        nodeIds: context.nodeIds,
        text: calleeText,
      }),
    );
  });

  return facts;
}

export function collectRenderFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
  validatedTrustBoundaries: TrustBoundaryValidationState,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText && renderSinkNames.has(calleeText)) {
      const viewName = node.arguments[0];

      if (
        viewName &&
        viewName.type !== 'SpreadElement' &&
        isRequestDerivedExpression(viewName, taintedNames, context.sourceText) &&
        !isValidatedTrustBoundaryExpression(
          viewName,
          validatedTrustBoundaries,
          context.sourceText,
        )
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.userControlledViewRender,
            node,
            nodeIds: context.nodeIds,
            props: {
              sink: calleeText,
            },
            text: calleeText,
          }),
        );
      }
    }
  });

  return facts;
}

export function collectExpressHardeningFacts(
  context: TypeScriptFactDetectorContext,
  functionBindings: ReadonlyMap<string, FunctionLikeNode>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const objectBindings = collectObjectBindings(context);
  let expressInitNode: TSESTree.CallExpression | undefined;
  let helmetApplied = false;
  let reduceFingerprintApplied = false;
  let staticIndex = Number.POSITIVE_INFINITY;
  let sessionIndex = Number.POSITIVE_INFINITY;
  let callIndex = 0;

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (
      node.callee.type === 'Identifier' &&
      node.callee.name === 'express' &&
      !expressInitNode
    ) {
      expressInitNode = node;
    }

    if (
      calleeText === 'app.use' &&
      node.arguments[0] &&
      node.arguments[0].type !== 'SpreadElement'
    ) {
      callIndex += 1;
      const middlewareCall = resolveMiddlewareCallExpression(
        node.arguments[0],
        functionBindings,
      );
      const middlewareText = normalizeText(
        getNodeText(middlewareCall ?? node.arguments[0], context.sourceText),
      );
      const middlewareCalleeText = middlewareCall
        ? getCalleeText(middlewareCall.callee, context.sourceText)
        : undefined;

      if (middlewareCalleeText === 'helmet' || /^helmet\(/u.test(middlewareText)) {
        helmetApplied = true;

        const helmetConfig = resolveObjectExpression(
          middlewareCall?.arguments[0],
          objectBindings,
        );

        if (
          objectBooleanFlagFalse(helmetConfig, 'frameguard') ||
          objectBooleanFlagFalse(helmetConfig, 'contentSecurityPolicy')
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.uiRedress,
              node,
              nodeIds: context.nodeIds,
              text: middlewareCalleeText ?? 'helmet',
            }),
          );
        }
      }

      if (
        middlewareCalleeText === 'helmet.hidePoweredBy' ||
        middlewareCalleeText === 'hidePoweredBy' ||
        /^helmet\.hidePoweredBy\(/u.test(middlewareText) ||
        /^hidePoweredBy\(/u.test(middlewareText)
      ) {
        reduceFingerprintApplied = true;
      }

      if (
        (middlewareCalleeText === 'express.static' ||
          /^express\.static\(/u.test(middlewareText)) &&
        staticIndex === Number.POSITIVE_INFINITY
      ) {
        staticIndex = callIndex;
      }

      if (
        ((middlewareCalleeText && sessionCallNames.has(middlewareCalleeText)) ||
          /^session\(/u.test(middlewareText) ||
          /^cookieSession\(/u.test(middlewareText)) &&
        sessionIndex === Number.POSITIVE_INFINITY
      ) {
        sessionIndex = callIndex;
      }
    }

    if (
      calleeText === 'app.disable' &&
      getLiteralString(node.arguments[0] as TSESTree.Expression) ===
        'x-powered-by'
    ) {
      reduceFingerprintApplied = true;
    }

    if (calleeText && sessionCallNames.has(calleeText)) {
      const config = resolveObjectExpression(node.arguments[0], objectBindings);

      if (config) {
        const cookieConfig = getSessionCookieConfig(
          calleeText,
          config,
          objectBindings,
        );

        if (objectBooleanFlagFalse(cookieConfig, 'httpOnly')) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.insecureCookieHttpOnly,
              node,
              nodeIds: context.nodeIds,
              text: calleeText,
            }),
          );
        }

        if (objectBooleanFlagFalse(cookieConfig, 'secure')) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.insecureCookie,
              node,
              nodeIds: context.nodeIds,
              text: calleeText,
            }),
          );
        }

        if (calleeText === 'session' && !getObjectProperty(config, 'name')) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.expressDefaultSessionConfig,
              node,
              nodeIds: context.nodeIds,
              text: calleeText,
            }),
          );
        }

        if (calleeText === 'cookieSession') {
          if (cookieConfig && !hasExplicitCookieAttributes(cookieConfig)) {
            facts.push(
              createObservedFact({
                appliesTo: 'block',
                kind: FACT_KINDS.expressDefaultCookieConfig,
                node,
                nodeIds: context.nodeIds,
                text: calleeText,
              }),
            );
          }
        }

        if (
          calleeText === 'session' &&
          cookieConfig &&
          !hasExplicitCookieAttributes(cookieConfig)
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.expressDefaultCookieConfig,
              node,
              nodeIds: context.nodeIds,
              text: calleeText,
            }),
          );
        }

        const permissiveCookieReasons = cookieConfig
          ? getPermissiveCookieReasons(cookieConfig)
          : [];

        if (permissiveCookieReasons.length > 0) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.expressPermissiveCookieConfig,
              node,
              nodeIds: context.nodeIds,
              props: {
                reasons: permissiveCookieReasons,
              },
              text: calleeText,
            }),
          );
        }
      }
    }

    if (
      (calleeText === 'expressjwt' || calleeText === 'expressJwt') &&
      node.arguments[0] &&
      node.arguments[0].type !== 'SpreadElement'
    ) {
      const config = resolveObjectExpression(node.arguments[0], objectBindings);
      const hasSecret = Boolean(getObjectProperty(config, 'secret'));
      const hasIsRevoked = Boolean(
        getObjectProperty(config, 'isRevoked'),
      );

      if (hasSecret && !hasIsRevoked) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.jwtNotRevoked,
            node,
            nodeIds: context.nodeIds,
            text: calleeText,
          }),
        );
      }
    }

  });

  if (
    staticIndex > sessionIndex &&
    Number.isFinite(staticIndex) &&
    Number.isFinite(sessionIndex)
  ) {
    if (expressInitNode) {
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: FACT_KINDS.expressStaticAssetsAfterSession,
          node: expressInitNode,
          nodeIds: context.nodeIds,
          text: 'app.use',
        }),
      );
    }
  }

  if (expressInitNode && !helmetApplied) {
    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: FACT_KINDS.expressMissingHelmet,
        node: expressInitNode,
        nodeIds: context.nodeIds,
        text: 'express',
      }),
    );
  }

  if (expressInitNode && !reduceFingerprintApplied) {
    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: FACT_KINDS.expressReduceFingerprint,
        node: expressInitNode,
        nodeIds: context.nodeIds,
        text: 'express',
      }),
    );
  }

  return facts;
}
