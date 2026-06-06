import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isExplicitDevOnlyContext } from './additional-public-security/disclosure';
import { FACT_KINDS } from './additional-public-security/constants';
import { isAllInterfacesHostname } from './outbound-network';
import {
  createObservedFact,
  excerptFor,
  getCalleeText,
  getObjectProperty,
  getStringLiteralValue,
  walkAstWithAncestors,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

const TLS_SERVER_BOOTSTRAP_PATTERN =
  /\b(?:https|http2)\.create(?:Secure)?Server\s*\(/u;
const TLS_TERMINATION_GUARD_PATTERN =
  /\b(?:TRUST_PROXY|TLS_TERMINAT(?:ED|ION)|BEHIND_(?:PROXY|LB|LOAD_BALANCER)|REVERSE_PROXY|INGRESS|API_GATEWAY|TERMINAT(?:ES|ING)_TLS)\b/u;

function sourceHasTlsServerBootstrap(sourceText: string): boolean {
  return TLS_SERVER_BOOTSTRAP_PATTERN.test(sourceText);
}

function sourceHasTlsTerminationGuard(sourceText: string): boolean {
  return (
    TLS_TERMINATION_GUARD_PATTERN.test(sourceText) ||
    /\btrustProxy\b/u.test(sourceText) ||
    /\b(?:set|enable)\s*\(\s*['"]trust proxy['"]/iu.test(sourceText) ||
    /@fastify\/(?:http-proxy|proxy)/u.test(sourceText) ||
    /\bX-Forwarded-Proto\b/u.test(sourceText)
  );
}

function unwrapAwaitExpression(
  expression: TSESTree.Expression | null | undefined,
): TSESTree.Expression | null | undefined {
  if (!expression) {
    return undefined;
  }

  if (expression.type === 'AwaitExpression') {
    return unwrapAwaitExpression(expression.argument as TSESTree.Expression);
  }

  return expression;
}

function getInitializerCalleeName(
  init: TSESTree.Expression | null | undefined,
): string | undefined {
  const expression = unwrapAwaitExpression(init ?? undefined);

  if (!expression) {
    return undefined;
  }

  if (expression.type !== 'CallExpression' && expression.type !== 'NewExpression') {
    return undefined;
  }

  if (expression.callee.type === 'Identifier') {
    return expression.callee.name;
  }

  if (
    expression.callee.type === 'MemberExpression' &&
    expression.callee.property.type === 'Identifier'
  ) {
    return expression.callee.property.name;
  }

  return undefined;
}

function isNestFactoryCreate(
  init: TSESTree.Expression | null | undefined,
): boolean {
  const expression = unwrapAwaitExpression(init ?? undefined);

  if (!expression || expression.type !== 'CallExpression') {
    return false;
  }

  if (
    expression.callee.type !== 'MemberExpression' ||
    expression.callee.property.type !== 'Identifier' ||
    expression.callee.property.name !== 'create'
  ) {
    return false;
  }

  if (expression.callee.object.type !== 'Identifier') {
    return false;
  }

  return expression.callee.object.name === 'NestFactory';
}

function collectFrameworkAppNames(context: TypeScriptFactDetectorContext): Set<string> {
  const appNames = new Set<string>();

  walkAstWithAncestors(context.program, (node) => {
    if (node.type !== 'VariableDeclarator' || node.id.type !== 'Identifier') {
      return;
    }

    const calleeName = getInitializerCalleeName(node.init);

    if (
      calleeName === 'express' ||
      calleeName === 'Fastify' ||
      calleeName === 'fastify' ||
      isNestFactoryCreate(node.init)
    ) {
      appNames.add(node.id.name);
    }
  });

  return appNames;
}

function listenUsesPublicHost(
  node: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  const firstArgument = node.arguments[0];

  if (
    firstArgument &&
    firstArgument.type !== 'SpreadElement' &&
    firstArgument.type === 'ObjectExpression'
  ) {
    for (const propertyName of ['host', 'hostname']) {
      const property = getObjectProperty(firstArgument, propertyName);
      const host = getStringLiteralValue(property?.value as TSESTree.Expression);

      if (host && isAllInterfacesHostname(host)) {
        return true;
      }
    }
  }

  const hostArgument = node.arguments[1];

  if (
    hostArgument &&
    hostArgument.type !== 'SpreadElement' &&
    hostArgument.type === 'Literal' &&
    typeof hostArgument.value === 'string' &&
    isAllInterfacesHostname(hostArgument.value)
  ) {
    return true;
  }

  return false;
}

function isFrameworkListenOnPublicHost(
  node: TSESTree.CallExpression,
  frameworkAppNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  if (
    node.callee.type !== 'MemberExpression' ||
    node.callee.property.type !== 'Identifier' ||
    node.callee.property.name !== 'listen' ||
    node.callee.object.type !== 'Identifier' ||
    !frameworkAppNames.has(node.callee.object.name)
  ) {
    return false;
  }

  return listenUsesPublicHost(node, sourceText);
}

export const collectInsecureServerListenFacts: TypeScriptFactDetector = (
  context,
) => {
  const sourceText = context.sourceText;

  if (
    sourceHasTlsServerBootstrap(sourceText) ||
    sourceHasTlsTerminationGuard(sourceText)
  ) {
    return [];
  }

  const facts: ObservedFact[] = [];
  const frameworkAppNames = collectFrameworkAppNames(context);

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (isExplicitDevOnlyContext(node, ancestors, sourceText)) {
      return;
    }

    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, sourceText);

    if (calleeText === 'http.createServer') {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.expressInsecureListen,
          node,
          nodeIds: context.nodeIds,
          props: {
            sink: calleeText,
          },
          text: excerptFor(node, sourceText),
        }),
      );
      return;
    }

    if (isFrameworkListenOnPublicHost(node, frameworkAppNames, sourceText)) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.expressInsecureListen,
          node,
          nodeIds: context.nodeIds,
          props: {
            sink: getCalleeText(node.callee, sourceText) ?? 'listen',
          },
          text: excerptFor(node, sourceText),
        }),
      );
    }
  });

  return facts;
};
