import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  collectObjectBindings,
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  resolveObjectExpression,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';

import { getLiteralString } from './literal-values';
import { FACT_KINDS } from './constants';
import { objectBooleanFlagFalse } from './object-flags';

const FASTIFY_EXCESSIVE_BODY_LIMIT = 10 * 1024 * 1024;
const FASTIFY_ROUTE_METHOD_NAMES = new Set([
  'delete',
  'get',
  'head',
  'options',
  'patch',
  'post',
  'put',
  'route',
]);

const APOLLO_DEV_TOOLING_PATTERN =
  /ApolloServerPluginLandingPageLocalDefault|ApolloServerPluginLandingPageGraphQLPlayground|ApolloSandbox|PluginGraphiQL|GraphiQLPlugin|graphql-playground-html|@as-integrations\/.*[Pp]layground/u;

const APOLLO_DEV_TOOLING_SAFE_GUARD =
  /NODE_ENV|import\.meta\.env\.(PROD|MODE|DEV)|['"]production['"]|['"]development['"]/u;

function getFastifyCalleeName(
  callee: TSESTree.Expression | TSESTree.PrivateIdentifier,
): string | undefined {
  if (callee.type === 'Identifier') {
    return callee.name;
  }

  return undefined;
}

function readPositiveNumericLiteral(
  expression: TSESTree.Expression | undefined,
): number | undefined {
  if (!expression) {
    return undefined;
  }

  if (expression.type === 'Literal' && typeof expression.value === 'number') {
    return expression.value;
  }

  return undefined;
}

function resolveFastifyRootOptions(
  expression:
    | TSESTree.Expression
    | TSESTree.SpreadElement
    | TSESTree.PrivateIdentifier
    | undefined,
  objectBindings: ReadonlyMap<string, TSESTree.ObjectExpression>,
): TSESTree.ObjectExpression | undefined {
  if (
    !expression ||
    expression.type === 'SpreadElement' ||
    expression.type === 'PrivateIdentifier'
  ) {
    return undefined;
  }

  return resolveObjectExpression(expression, objectBindings);
}

function unwrapAwaitExpression(
  expression: TSESTree.Expression | undefined,
): TSESTree.Expression | undefined {
  if (!expression) {
    return undefined;
  }

  if (expression.type === 'AwaitExpression') {
    return unwrapAwaitExpression(
      expression.argument as TSESTree.Expression | undefined,
    );
  }

  return expression;
}

function fastifyTrustProxyEnabled(
  options: TSESTree.ObjectExpression | undefined,
): boolean {
  if (!options) {
    return false;
  }

  const trustProp = getObjectProperty(options, 'trustProxy')?.value;

  if (trustProp?.type === 'Literal') {
    if (trustProp.value === true) {
      return true;
    }

    if (typeof trustProp.value === 'number' && trustProp.value >= 1) {
      return true;
    }
  }

  return false;
}

function sourceHasFastifyProxyCompensation(sourceText: string): boolean {
  return (
    sourceText.includes('@fastify/http-proxy') ||
    sourceText.includes('@fastify/proxy') ||
    /\b(API_GATEWAY|INGRESS|EDGE_PROXY|REVERSE_PROXY)\b/u.test(sourceText)
  );
}

function listenArgumentsUsePublicHost(
  args: readonly TSESTree.CallExpressionArgument[],
): boolean {
  const first = args[0];

  if (first?.type === 'ObjectExpression') {
    const hostProp = getObjectProperty(first, 'host');
    const hostVal = getLiteralString(hostProp?.value);

    if (hostVal === '0.0.0.0' || hostVal === '::') {
      return true;
    }
  }

  const second = args[1];

  if (second && second.type !== 'SpreadElement') {
    const hostVal = getLiteralString(second as TSESTree.Expression);

    if (hostVal === '0.0.0.0' || hostVal === '::') {
      return true;
    }
  }

  return false;
}

function collectFastifyTrustProxyFacts(
  context: TypeScriptFactDetectorContext,
  objectBindings: ReadonlyMap<string, TSESTree.ObjectExpression>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const fastifyApps = new Map<string, boolean>();

  walkAst(context.program, (node) => {
    if (node.type !== 'VariableDeclarator' || node.id.type !== 'Identifier') {
      return;
    }

    const init = unwrapAwaitExpression(node.init as TSESTree.Expression);

    if (
      !init ||
      (init.type !== 'CallExpression' && init.type !== 'NewExpression')
    ) {
      return;
    }

    const calleeName = getFastifyCalleeName(init.callee);

    if (
      !calleeName ||
      (calleeName !== 'Fastify' && calleeName !== 'fastify')
    ) {
      return;
    }

    const rootOptions = resolveFastifyRootOptions(
      init.arguments[0],
      objectBindings,
    );

    fastifyApps.set(node.id.name, fastifyTrustProxyEnabled(rootOptions));
  });

  if (fastifyApps.size === 0) {
    return facts;
  }

  const suppressProxy = sourceHasFastifyProxyCompensation(context.sourceText);

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (
      node.callee.type !== 'MemberExpression' ||
      node.callee.property.type !== 'Identifier' ||
      node.callee.property.name !== 'listen' ||
      node.callee.object.type !== 'Identifier'
    ) {
      return;
    }

    const receiver = node.callee.object.name;

    if (!fastifyApps.has(receiver)) {
      return;
    }

    if (fastifyApps.get(receiver)) {
      return;
    }

    if (suppressProxy) {
      return;
    }

    if (!listenArgumentsUsePublicHost(node.arguments)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.fastifyPublicBindWithoutTrustProxy,
        node,
        nodeIds: context.nodeIds,
        text: 'listen',
      }),
    );
  });

  return facts;
}

function apolloBootstrapIndicatesLimits(
  config: TSESTree.ObjectExpression | undefined,
  sourceText: string,
): boolean {
  if (!config) {
    return false;
  }

  const validationRules = getObjectProperty(config, 'validationRules')?.value;

  if (
    validationRules?.type === 'ArrayExpression' &&
    validationRules.elements.some(Boolean)
  ) {
    return true;
  }

  const plugins = getObjectProperty(config, 'plugins')?.value;

  if (plugins?.type === 'ArrayExpression') {
    for (const element of plugins.elements) {
      if (!element || element.type === 'SpreadElement') {
        continue;
      }

      const snippet = getNodeText(element, sourceText) ?? '';

      if (
        /depth|complexity|cost|persist|r(?:ate)?[\s_-]?limit|query.?cost/i.test(
          snippet,
        )
      ) {
        return true;
      }
    }
  }

  if (getObjectProperty(config, 'gateway')) {
    return true;
  }

  return false;
}

function sourceIndicatesInternalOnlyGraphql(sourceText: string): boolean {
  return (
    /\b(?:127\.0\.0\.1|localhost)\b/u.test(sourceText) ||
    /host\s*:\s*['"](?:127\.0\.0\.1|localhost)['"]/u.test(sourceText) ||
    /\binternal[-_. ]only\b/iu.test(sourceText)
  );
}

function sourceIndicatesExternalGraphqlProtection(sourceText: string): boolean {
  return (
    sourceText.includes('ApolloGateway') ||
    /\bcreateComplexityLimitRule\b/u.test(sourceText) ||
    /\bdepthLimit\b/u.test(sourceText) ||
    /graphql-rate-limit/u.test(sourceText)
  );
}

function introspectionIsLiteralTrue(
  expression: TSESTree.Property['value'] | undefined,
): boolean {
  return expression?.type === 'Literal' && expression.value === true;
}

function collectApolloDevToolingExposureFacts(
  config: TSESTree.ObjectExpression | undefined,
  apolloNode: TSESTree.NewExpression,
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (!config) {
    return facts;
  }

  const plugins = getObjectProperty(config, 'plugins')?.value;

  if (plugins?.type !== 'ArrayExpression') {
    return facts;
  }

  const sourceText = context.sourceText;

  for (const element of plugins.elements) {
    if (!element || element.type === 'SpreadElement') {
      continue;
    }

    const snippet = getNodeText(element, sourceText) ?? '';

    if (!APOLLO_DEV_TOOLING_PATTERN.test(snippet)) {
      continue;
    }

    if (APOLLO_DEV_TOOLING_SAFE_GUARD.test(snippet)) {
      continue;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.apolloServerGraphqlDevToolingExposure,
        node: apolloNode,
        nodeIds: context.nodeIds,
        text: 'ApolloServer',
      }),
    );
    break;
  }

  return facts;
}

function calleeLooksLikeGraphqlUpload(
  callee: TSESTree.Expression | TSESTree.PrivateIdentifier,
  sourceText: string,
): boolean {
  if (callee.type === 'PrivateIdentifier') {
    return false;
  }

  const text = getCalleeText(callee, sourceText) ?? '';

  return (
    /\bgraphqlUploadExpress$/u.test(text) ||
    /\bgraphqlUploadKoa$/u.test(text) ||
    /\bgraphqlUploadMiddleware$/u.test(text) ||
    (callee.type === 'Identifier' && callee.name === 'graphqlUpload')
  );
}

function apolloCsrfNeverExplicitlyDisabledInFile(
  program: TSESTree.Program,
  objectBindings: ReadonlyMap<string, TSESTree.ObjectExpression>,
  sourceText: string,
): boolean {
  let sawApollo = false;
  let csrfExplicitlyDisabled = false;

  walkAst(program, (node) => {
    if (node.type !== 'NewExpression') {
      return;
    }

    if (getCalleeText(node.callee, sourceText) !== 'ApolloServer') {
      return;
    }

    sawApollo = true;

    const config = resolveFastifyRootOptions(
      node.arguments[0],
      objectBindings,
    );

    if (objectBooleanFlagFalse(config, 'csrfPrevention')) {
      csrfExplicitlyDisabled = true;
    }
  });

  return sawApollo && !csrfExplicitlyDisabled;
}

function collectGraphqlUploadCsrfFacts(
  context: TypeScriptFactDetectorContext,
  objectBindings: ReadonlyMap<string, TSESTree.ObjectExpression>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (
    apolloCsrfNeverExplicitlyDisabledInFile(
      context.program,
      objectBindings,
      context.sourceText,
    )
  ) {
    return facts;
  }

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (!calleeLooksLikeGraphqlUpload(node.callee, context.sourceText)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.graphqlUploadWithoutCsrfGuard,
        node,
        nodeIds: context.nodeIds,
        text: getCalleeText(node.callee, context.sourceText) ?? 'graphqlUpload',
      }),
    );
  });

  return facts;
}

export function collectNodeFrameworkBootstrapFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const objectBindings = collectObjectBindings(context);
  const sourceText = context.sourceText;
  const fastifyAppNames = new Set<string>();

  walkAst(context.program, (node) => {
    if (node.type !== 'VariableDeclarator' || node.id.type !== 'Identifier') {
      return;
    }

    const init = unwrapAwaitExpression(node.init as TSESTree.Expression | undefined);
    if (!init || (init.type !== 'CallExpression' && init.type !== 'NewExpression')) {
      return;
    }

    const calleeName = getFastifyCalleeName(init.callee);
    if (calleeName === 'Fastify' || calleeName === 'fastify') {
      fastifyAppNames.add(node.id.name);
    }
  });

  walkAst(context.program, (node) => {
    if (node.type === 'CallExpression' || node.type === 'NewExpression') {
      const calleeName = getFastifyCalleeName(node.callee);

      if (
        calleeName &&
        (calleeName === 'Fastify' || calleeName === 'fastify')
      ) {
        const rootOptions = resolveFastifyRootOptions(
          node.arguments[0],
          objectBindings,
        );
        const bodyLimitProp = rootOptions
          ? getObjectProperty(rootOptions, 'bodyLimit')
          : undefined;
        const limitValue = readPositiveNumericLiteral(
          bodyLimitProp?.value as TSESTree.Expression | undefined,
        );

        if (
          typeof limitValue === 'number' &&
          (limitValue >= FASTIFY_EXCESSIVE_BODY_LIMIT || limitValue === 0)
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.fastifyExcessiveBodyLimit,
              node,
              nodeIds: context.nodeIds,
              text: calleeName,
              props: {
                bodyLimit: limitValue,
              },
            }),
          );
        }
      }
    }

    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      node.callee.object.type === 'Identifier' &&
      node.callee.property.type === 'Identifier' &&
      fastifyAppNames.has(node.callee.object.name) &&
      FASTIFY_ROUTE_METHOD_NAMES.has(node.callee.property.name)
    ) {
      const routeOptionsArg = node.arguments.find(
        (argument) => argument.type === 'ObjectExpression',
      );
      const bodyLimitProp =
        routeOptionsArg?.type === 'ObjectExpression'
          ? getObjectProperty(routeOptionsArg, 'bodyLimit')
          : undefined;
      const limitValue = readPositiveNumericLiteral(
        bodyLimitProp?.value as TSESTree.Expression | undefined,
      );

      if (
        typeof limitValue === 'number' &&
        (limitValue >= FASTIFY_EXCESSIVE_BODY_LIMIT || limitValue === 0)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.fastifyExcessiveBodyLimit,
            node,
            nodeIds: context.nodeIds,
            text: `${node.callee.object.name}.${node.callee.property.name}`,
            props: {
              bodyLimit: limitValue,
            },
          }),
        );
      }
    }

    if (node.type !== 'NewExpression') {
      return;
    }

    const ctorText = getCalleeText(node.callee, sourceText);

    if (ctorText !== 'ApolloServer') {
      return;
    }

    const config = resolveFastifyRootOptions(
      node.arguments[0],
      objectBindings,
    );

    if (objectBooleanFlagFalse(config, 'csrfPrevention')) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.apolloServerCsrfDisabled,
          node,
          nodeIds: context.nodeIds,
          text: ctorText,
        }),
      );
    }

    const introspectionProp = config
      ? getObjectProperty(config, 'introspection')
      : undefined;

    if (introspectionIsLiteralTrue(introspectionProp?.value)) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.apolloServerIntrospectionExposure,
          node,
          nodeIds: context.nodeIds,
          text: ctorText,
        }),
      );
    }

    const hasBootstrapLimits = apolloBootstrapIndicatesLimits(
      config,
      sourceText,
    );
    const hasExternalProtection =
      sourceIndicatesExternalGraphqlProtection(sourceText);
    const internalOnly = sourceIndicatesInternalOnlyGraphql(sourceText);

    if (config && !hasBootstrapLimits && !hasExternalProtection && !internalOnly) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.apolloServerMissingQueryLimits,
          node,
          nodeIds: context.nodeIds,
          text: ctorText,
        }),
      );
    }

    facts.push(
      ...collectApolloDevToolingExposureFacts(config, node, context),
    );
  });

  facts.push(...collectFastifyTrustProxyFacts(context, objectBindings));
  facts.push(...collectGraphqlUploadCsrfFacts(context, objectBindings));

  return facts;
}
