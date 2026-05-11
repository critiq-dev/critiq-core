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

import { FACT_KINDS } from './constants';
import { objectBooleanFlagFalse } from './object-flags';

const FASTIFY_EXCESSIVE_BODY_LIMIT = 10 * 1024 * 1024;

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

export function collectNodeFrameworkBootstrapFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const objectBindings = collectObjectBindings(context);
  const sourceText = context.sourceText;

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

    if (config && !hasBootstrapLimits && !hasExternalProtection) {
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
  });

  return facts;
}
