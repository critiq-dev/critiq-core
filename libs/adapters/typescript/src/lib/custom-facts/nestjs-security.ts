import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  collectObjectBindings,
  createObservedFact,
  getCalleeText,
  getObjectProperty,
  resolveObjectExpression,
  walkAst,
  type TypeScriptFactDetectorContext,
} from './shared';

import { FACT_KINDS } from './additional-public-security/constants';

type NestMethodDefinition = TSESTree.MethodDefinition & {
  decorators?: TSESTree.Decorator[];
};

const SENSITIVE_ROUTE_SEGMENT =
  /(?:^|\/)(?:login|signin|sign-in|logout|password|reset|otp|token|refresh|mfa|2fa|auth)(?:\/|$)/iu;

function unwrapAwaitExpression(
  expression: TSESTree.Expression | undefined,
): TSESTree.Expression | undefined {
  if (!expression) {
    return undefined;
  }

  if (expression.type === 'AwaitExpression') {
    return unwrapAwaitExpression(expression.argument as TSESTree.Expression);
  }

  return expression;
}

function collectNestApplicationRoots(
  context: TypeScriptFactDetectorContext,
): Map<string, TSESTree.CallExpression> {
  const roots = new Map<string, TSESTree.CallExpression>();

  walkAst(context.program, (node: TSESTree.Node) => {
    if (node.type !== 'VariableDeclarator') {
      return;
    }

    const init = unwrapAwaitExpression(node.init as TSESTree.Expression | undefined);

    if (!init || init.type !== 'CallExpression') {
      return;
    }

    if (getCalleeText(init.callee, context.sourceText) !== 'NestFactory.create') {
      return;
    }

    if (node.id.type === 'Identifier') {
      roots.set(node.id.name, init);
    }
  });

  return roots;
}

function classifyNestUseMiddleware(
  node: TSESTree.CallExpression,
  sourceText: string,
): 'helmet' | 'route-mount' | 'other' {
  const firstArgument = node.arguments[0];

  if (!firstArgument || firstArgument.type === 'SpreadElement') {
    return 'other';
  }

  if (firstArgument.type === 'CallExpression') {
    const nestedCallee = getCalleeText(firstArgument.callee, sourceText);

    if (nestedCallee === 'helmet' || /^helmet$/u.test(nestedCallee ?? '')) {
      return 'helmet';
    }
  }

  const secondArgument = node.arguments[1];

  const firstIsPathLiteral =
    firstArgument.type === 'Literal' && typeof firstArgument.value === 'string';
  const firstIsStaticTemplate =
    firstArgument.type === 'TemplateLiteral' && firstArgument.expressions.length === 0;

  if ((firstIsPathLiteral || firstIsStaticTemplate) && secondArgument) {
    if (secondArgument.type !== 'SpreadElement') {
      return 'route-mount';
    }
  }

  return 'other';
}

function collectHelmetOrderingFacts(
  context: TypeScriptFactDetectorContext,
  nestAppRoots: Map<string, TSESTree.CallExpression>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (nestAppRoots.size === 0) {
    return facts;
  }

  type PositionedUse = {
    line: number;
    kind: ReturnType<typeof classifyNestUseMiddleware>;
    node: TSESTree.CallExpression;
  };

  const usesByApp = new Map<string, PositionedUse[]>();

  walkAst(context.program, (node: TSESTree.Node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (node.callee.type !== 'MemberExpression') {
      return;
    }

    if (
      node.callee.property.type !== 'Identifier' ||
      node.callee.property.name !== 'use'
    ) {
      return;
    }

    if (node.callee.object.type !== 'Identifier') {
      return;
    }

    const appName = node.callee.object.name;

    if (!nestAppRoots.has(appName)) {
      return;
    }

    const line = node.loc?.start.line ?? 0;
    const kind = classifyNestUseMiddleware(node, context.sourceText);
    const bucket = usesByApp.get(appName) ?? [];
    bucket.push({ line, kind, node });
    usesByApp.set(appName, bucket);
  });

  for (const [, uses] of usesByApp) {
    const sortedUses = [...uses].sort((left, right) => left.line - right.line);
    const firstHelmet = sortedUses.find((entry) => entry.kind === 'helmet');

    if (!firstHelmet) {
      continue;
    }

    const routeMountedBeforeHelmet = sortedUses.some(
      (entry) => entry.kind === 'route-mount' && entry.line < firstHelmet.line,
    );

    if (routeMountedBeforeHelmet) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.nestjsHelmetAfterRouteMount,
          node: firstHelmet.node,
          nodeIds: context.nodeIds,
          text: 'helmet',
        }),
      );
    }
  }

  return facts;
}

function validationPipeOptionsMissingWhitelist(
  options: TSESTree.ObjectExpression | undefined,
): boolean {
  const whitelistProperty = options
    ? getObjectProperty(options, 'whitelist')
    : undefined;

  return !(
    whitelistProperty?.value.type === 'Literal' &&
    whitelistProperty.value.value === true
  );
}

function collectValidationPipeFacts(
  context: TypeScriptFactDetectorContext,
  nestAppRoots: Map<string, TSESTree.CallExpression>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (nestAppRoots.size === 0) {
    return facts;
  }

  const objectBindings = collectObjectBindings(context);
  const nestAppNames = new Set(nestAppRoots.keys());
  const appsWithGlobalPipes = new Set<string>();

  walkAst(context.program, (node: TSESTree.Node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (
      node.callee.type !== 'MemberExpression' ||
      node.callee.property.type !== 'Identifier' ||
      node.callee.property.name !== 'useGlobalPipes'
    ) {
      return;
    }

    if (node.callee.object.type !== 'Identifier') {
      return;
    }

    const receiverName = node.callee.object.name;

    if (!nestAppNames.has(receiverName)) {
      return;
    }

    appsWithGlobalPipes.add(receiverName);

    for (const argument of node.arguments) {
      if (!argument || argument.type === 'SpreadElement') {
        continue;
      }

      if (argument.type !== 'NewExpression') {
        continue;
      }

      const ctorText = getCalleeText(argument.callee, context.sourceText);

      if (ctorText !== 'ValidationPipe') {
        continue;
      }

      const config = resolveObjectExpression(argument.arguments[0], objectBindings);

      if (validationPipeOptionsMissingWhitelist(config)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.nestjsValidationPipeWithoutWhitelist,
            node: argument,
            nodeIds: context.nodeIds,
            text: 'ValidationPipe',
          }),
        );
      }
    }
  });

  for (const [appName, init] of nestAppRoots) {
    if (!appsWithGlobalPipes.has(appName)) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.nestjsMissingGlobalValidationPipe,
          node: init,
          nodeIds: context.nodeIds,
          text: 'NestFactory.create',
        }),
      );
    }
  }

  return facts;
}

function decoratorCalleeName(
  decorator: TSESTree.Decorator,
  sourceText: string,
): string | undefined {
  if (decorator.expression.type !== 'CallExpression') {
    return undefined;
  }

  return getCalleeText(decorator.expression.callee, sourceText);
}

function readHttpDecoratorRoute(
  decorator: TSESTree.Decorator,
  sourceText: string,
): string | undefined {
  if (decorator.expression.type !== 'CallExpression') {
    return undefined;
  }

  const calleeText = getCalleeText(decorator.expression.callee, sourceText);

  if (
    !calleeText ||
    !['Post', 'Get', 'Put', 'Patch', 'Delete'].includes(calleeText)
  ) {
    return undefined;
  }

  const pathArgument = decorator.expression.arguments[0];

  if (
    pathArgument?.type === 'Literal' &&
    typeof pathArgument.value === 'string'
  ) {
    return pathArgument.value;
  }

  return undefined;
}

function collectSkipThrottleFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (/\.spec\.[tj]s$/iu.test(context.path) || /\.e2e\.[tj]s$/iu.test(context.path)) {
    return facts;
  }

  walkAst(context.program, (node: TSESTree.Node) => {
    if (node.type !== 'MethodDefinition') {
      return;
    }

    const method = node as NestMethodDefinition;
    const decorators = method.decorators;

    if (!decorators?.length) {
      return;
    }

    const skipThrottleDecorator = decorators.find(
      (decorator) => decoratorCalleeName(decorator, context.sourceText) === 'SkipThrottle',
    );

    if (!skipThrottleDecorator) {
      return;
    }

    const hasThrottleDecorator = decorators.some(
      (decorator) => decoratorCalleeName(decorator, context.sourceText) === 'Throttle',
    );

    const hasCompensatingDecorator = decorators.some((decorator) => {
      const decoratorName = decoratorCalleeName(decorator, context.sourceText);
      if (!decoratorName) {
        return false;
      }

      if (decoratorName === 'Throttle') {
        return true;
      }

      if (decorator.expression.type !== 'CallExpression') {
        return false;
      }

      if (
        decoratorName !== 'UseGuards' &&
        decoratorName !== 'UseInterceptors' &&
        decoratorName !== 'SetMetadata'
      ) {
        return false;
      }

      return decorator.expression.arguments.some((argument) => {
        if (argument.type === 'SpreadElement') {
          return false;
        }

        const snippet = getCalleeText(argument as TSESTree.Expression, context.sourceText);
        const text = snippet ?? context.sourceText.slice(argument.range[0], argument.range[1]);
        return /(rate|throttle|limit|auth|guard)/iu.test(text);
      });
    });

    if (hasThrottleDecorator || hasCompensatingDecorator) {
      return;
    }

    const route =
      decorators
        .map((decorator) => readHttpDecoratorRoute(decorator, context.sourceText))
        .find(Boolean) ?? '';

    if (!route || !SENSITIVE_ROUTE_SEGMENT.test(route)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.nestjsSkipThrottleSensitiveRoute,
        node: skipThrottleDecorator.expression as TSESTree.Node,
        nodeIds: context.nodeIds,
        text: route,
      }),
    );
  });

  return facts;
}

export function collectNestJsSecurityFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const nestAppRoots = collectNestApplicationRoots(context);

  return [
    ...collectHelmetOrderingFacts(context, nestAppRoots),
    ...collectValidationPipeFacts(context, nestAppRoots),
    ...collectSkipThrottleFacts(context),
  ];
}
