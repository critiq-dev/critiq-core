import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isAuthSecretPropertyName } from '../../auth-vocabulary';
import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { isRequestDerivedExpression } from './analysis';
import {
  FACT_KINDS,
  renderSinkNames,
  sensitiveComparePattern,
  sessionCallNames,
  strategyNames,
} from './constants';
import {
  getLiteralString,
  normalizeText,
  objectBooleanFlagFalse,
  objectPropertyNames,
} from './utils';

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

export function collectHardcodedAuthSecretFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

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
        configArgument.type !== 'SpreadElement' &&
        configArgument.type === 'ObjectExpression'
      ) {
        const secretProperty = findAuthSecretProperty(
          configArgument,
          context.sourceText,
        );

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

    const config = node.arguments[0];

    if (!config || config.type !== 'ObjectExpression') {
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
        isRequestDerivedExpression(viewName, taintedNames, context.sourceText)
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
): ObservedFact[] {
  const facts: ObservedFact[] = [];
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
      const middlewareText = normalizeText(
        getNodeText(node.arguments[0], context.sourceText),
      );

      if (/^helmet\(/u.test(middlewareText)) {
        helmetApplied = true;
      }

      if (
        /^helmet\.hidePoweredBy\(/u.test(middlewareText) ||
        /^hidePoweredBy\(/u.test(middlewareText)
      ) {
        reduceFingerprintApplied = true;
      }

      if (
        /^express\.static\(/u.test(middlewareText) &&
        staticIndex === Number.POSITIVE_INFINITY
      ) {
        staticIndex = callIndex;
      }

      if (
        /^session\(/u.test(middlewareText) &&
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
      const config = node.arguments[0];

      if (config && config.type === 'ObjectExpression') {
        let cookieConfig: TSESTree.ObjectExpression | undefined;

        if (calleeText === 'session') {
          const cookieProperty = getObjectProperty(config, 'cookie');
          cookieConfig =
            cookieProperty?.value.type === 'ObjectExpression'
              ? cookieProperty.value
              : undefined;
        } else {
          cookieConfig = config;
        }

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
          const propertyNames = objectPropertyNames(config);
          const hasAllCookieAttributes =
            propertyNames.has('name') &&
            (propertyNames.has('maxAge') || propertyNames.has('expires')) &&
            propertyNames.has('path') &&
            propertyNames.has('domain') &&
            propertyNames.has('secure') &&
            propertyNames.has('httpOnly');

          if (!hasAllCookieAttributes) {
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

        if (calleeText === 'session') {
          const cookieProperty = getObjectProperty(config, 'cookie');

          if (cookieProperty?.value.type === 'ObjectExpression') {
            const cookiePropertyNames = objectPropertyNames(
              cookieProperty.value,
            );
            const hasAllCookieAttributes =
              cookiePropertyNames.has('name') &&
              (cookiePropertyNames.has('maxAge') ||
                cookiePropertyNames.has('expires')) &&
              cookiePropertyNames.has('path') &&
              cookiePropertyNames.has('domain') &&
              cookiePropertyNames.has('secure') &&
              cookiePropertyNames.has('httpOnly');

            if (!hasAllCookieAttributes) {
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
        }
      }
    }

    if (
      (calleeText === 'expressjwt' || calleeText === 'expressJwt') &&
      node.arguments[0] &&
      node.arguments[0].type !== 'SpreadElement' &&
      node.arguments[0].type === 'ObjectExpression'
    ) {
      const hasSecret = Boolean(getObjectProperty(node.arguments[0], 'secret'));
      const hasIsRevoked = Boolean(
        getObjectProperty(node.arguments[0], 'isRevoked'),
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

    if (
      calleeText === 'argon2.hash' &&
      node.arguments[0] &&
      node.arguments[0].type !== 'SpreadElement' &&
      sensitiveComparePattern.test(
        normalizeText(getNodeText(node.arguments[0], context.sourceText)),
      )
    ) {
      const options = node.arguments[1];

      if (options && options.type === 'ObjectExpression') {
        const typeProperty = getObjectProperty(options, 'type');
        const typeText = normalizeText(
          getNodeText(typeProperty?.value, context.sourceText),
        );

        if (typeText === 'argon2.argon2i' || typeText === 'argon2.argon2d') {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.insecurePasswordHashConfig,
              node,
              nodeIds: context.nodeIds,
              props: {
                algorithm: typeText,
              },
              text: 'argon2.hash',
            }),
          );
        }
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
