import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  collectObjectBindings,
  createObservedFact,
  excerptFor,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  resolveObjectExpression,
  walkAst,
  walkFunctionBodySkippingNestedFunctions,
  type TypeScriptFactDetectorContext,
} from '../shared';
import {
  getStringLiteralArgument,
  isInsecureWebsocketUrl,
} from '../outbound-network';
import {
  hasOriginCheck,
  isRequestDerivedExpression,
  isValidatedTrustBoundaryExpression,
  resolveFunctionLike,
  type TrustBoundaryValidationState,
  type FunctionLikeNode,
} from './analysis';
import { FACT_KINDS } from './constants';
import { getLiteralString } from './utils';
import { trustBoundaryModuleLoaderCallees } from '../../trust-boundary';

function isUiRedressHeader(
  headerName: string,
): boolean {
  const normalizedHeader = headerName.toLowerCase();

  return (
    normalizedHeader === 'content-security-policy' ||
    normalizedHeader === 'x-frame-options'
  );
}

function hasDangerousUiRedressValue(
  headerName: string,
  headerValue: TSESTree.Expression | undefined,
): boolean {
  const literalValue = getLiteralString(headerValue);

  if (!literalValue) {
    return false;
  }

  const normalizedHeader = headerName.toLowerCase();
  const normalizedValue = literalValue.toLowerCase().replace(/\s+/gu, ' ').trim();

  if (normalizedHeader === 'x-frame-options') {
    return (
      normalizedValue === '*' ||
      normalizedValue === 'allowall' ||
      normalizedValue === 'off' ||
      normalizedValue === 'false' ||
      /^allow-from\s+\*$/u.test(normalizedValue)
    );
  }

  return /(?:^|;)\s*frame-ancestors\s+\*/u.test(normalizedValue);
}

function collectHeaderFacts(
  facts: ObservedFact[],
  context: TypeScriptFactDetectorContext,
  node: TSESTree.CallExpression,
  headerName: string,
  headerValue: TSESTree.Expression | undefined,
  taintedNames: ReadonlySet<string>,
): void {
  if (!headerValue) {
    return;
  }

  const normalizedHeader = headerName.toLowerCase();
  const requestDerived = isRequestDerivedExpression(
    headerValue,
    taintedNames,
    context.sourceText,
  );

  if (normalizedHeader === 'access-control-allow-origin') {
    if (requestDerived) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.insecureAllowOrigin,
          node,
          nodeIds: context.nodeIds,
          props: {
            header: headerName,
          },
          text: getCalleeText(node.callee, context.sourceText),
        }),
      );
      return;
    }

    if (getLiteralString(headerValue) === '*') {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.permissiveAllowOrigin,
          node,
          nodeIds: context.nodeIds,
          props: {
            header: headerName,
          },
          text: getCalleeText(node.callee, context.sourceText),
        }),
      );
    }

    return;
  }

  if (
    isUiRedressHeader(headerName) &&
    (requestDerived || hasDangerousUiRedressValue(headerName, headerValue))
  ) {
    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.uiRedress,
        node,
        nodeIds: context.nodeIds,
        props: {
          header: headerName,
        },
        text: getCalleeText(node.callee, context.sourceText),
      }),
    );
  }
}

function isSafeCorsOriginExpression(
  expression: TSESTree.Expression,
): boolean {
  if (expression.type === 'Literal') {
    if (typeof expression.value === 'string') {
      return expression.value !== '*';
    }

    return expression.value === false;
  }

  if (expression.type !== 'ArrayExpression') {
    return false;
  }

  return expression.elements.every(
    (element) =>
      element?.type === 'Literal' &&
      typeof element.value === 'string' &&
      element.value !== '*',
  );
}

function classifyCorsOriginCallback(
  handler: FunctionLikeNode,
): string | undefined {
  const originParam =
    handler.params[0]?.type === 'Identifier' ? handler.params[0] : undefined;
  const callbackParam =
    handler.params[1]?.type === 'Identifier' ? handler.params[1] : undefined;

  if (!callbackParam) {
    return undefined;
  }

  let classification: string | undefined;

  walkFunctionBodySkippingNestedFunctions(handler, (node) => {
    if (
      classification ||
      node.type !== 'CallExpression' ||
      node.callee.type !== 'Identifier' ||
      node.callee.name !== callbackParam.name
    ) {
      return;
    }

    const decisionArgument =
      node.arguments[1] && node.arguments[1].type !== 'SpreadElement'
        ? node.arguments[1]
        : undefined;

    if (!decisionArgument) {
      return;
    }

    if (
      decisionArgument.type === 'Literal' &&
      (decisionArgument.value === true || decisionArgument.value === '*')
    ) {
      classification = FACT_KINDS.permissiveAllowOrigin;
      return;
    }

    if (
      originParam &&
      decisionArgument.type === 'Identifier' &&
      decisionArgument.name === originParam.name
    ) {
      classification = FACT_KINDS.insecureAllowOrigin;
    }
  });

  if (classification) {
    return classification;
  }

  if (
    handler.body.type !== 'BlockStatement' &&
    handler.body.type === 'Literal' &&
    (handler.body.value === true || handler.body.value === '*')
  ) {
    return FACT_KINDS.permissiveAllowOrigin;
  }

  return undefined;
}

function classifyCorsConfig(
  node: TSESTree.CallExpression,
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
  objectBindings: ReadonlyMap<string, TSESTree.ObjectExpression>,
  functionBindings: ReadonlyMap<string, FunctionLikeNode>,
): string | undefined {
  if (node.arguments.length === 0) {
    return FACT_KINDS.permissiveAllowOrigin;
  }

  const firstArgument =
    node.arguments[0] && node.arguments[0].type !== 'SpreadElement'
      ? node.arguments[0]
      : undefined;

  if (!firstArgument) {
    return undefined;
  }

  const config = resolveObjectExpression(firstArgument, objectBindings);

  if (!config) {
    return undefined;
  }

  const originProperty = getObjectProperty(config, 'origin');

  if (!originProperty) {
    return FACT_KINDS.permissiveAllowOrigin;
  }

  const originValue = originProperty.value as TSESTree.Expression;

  if (
    isRequestDerivedExpression(originValue, taintedNames, context.sourceText)
  ) {
    return FACT_KINDS.insecureAllowOrigin;
  }

  if (
    originValue.type === 'Literal' &&
    (originValue.value === '*' || originValue.value === true)
  ) {
    return FACT_KINDS.permissiveAllowOrigin;
  }

  if (
    originValue.type === 'ArrayExpression' &&
    originValue.elements.some(
      (element) =>
        element?.type === 'Literal' &&
        typeof element.value === 'string' &&
        element.value === '*',
    )
  ) {
    return FACT_KINDS.permissiveAllowOrigin;
  }

  if (isSafeCorsOriginExpression(originValue)) {
    return undefined;
  }

  const callback = resolveFunctionLike(originValue, functionBindings);

  if (!callback) {
    return undefined;
  }

  return classifyCorsOriginCallback(callback);
}

export function collectHeaderMisuseFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
  functionBindings: ReadonlyMap<string, FunctionLikeNode>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const objectBindings = collectObjectBindings(context);

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText === 'cors') {
      const corsFactKind = classifyCorsConfig(
        node,
        context,
        taintedNames,
        objectBindings,
        functionBindings,
      );

      if (corsFactKind) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: corsFactKind,
            node,
            nodeIds: context.nodeIds,
            text: calleeText,
          }),
        );
      }
    }

    const headerName = getLiteralString(
      node.arguments[0] as TSESTree.Expression,
    );
    const headerValue = node.arguments[1] as TSESTree.Expression | undefined;

    if (
      calleeText &&
      /(?:^|\.)(header|set|setHeader)$/u.test(calleeText) &&
      headerName
    ) {
      collectHeaderFacts(
        facts,
        context,
        node,
        headerName,
        headerValue,
        taintedNames,
      );
    }

    if (calleeText !== 'res.writeHead') {
      return;
    }

    const headerBag = resolveObjectExpression(
      node.arguments[1],
      objectBindings,
    );

    if (!headerBag) {
      return;
    }

    for (const property of headerBag.properties) {
      if (property.type !== 'Property') {
        continue;
      }

      const header =
        property.key.type === 'Identifier'
          ? property.key.name
          : property.key.type === 'Literal' &&
              typeof property.key.value === 'string'
            ? property.key.value
            : undefined;

      if (!header) {
        continue;
      }

      collectHeaderFacts(
        facts,
        context,
        node,
        header,
        property.value as TSESTree.Expression,
        taintedNames,
      );
    }
  });

  return facts;
}

export function collectFormatStringFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);
    const firstArgument = node.arguments[0];

    if (
      !calleeText ||
      !firstArgument ||
      firstArgument.type === 'SpreadElement'
    ) {
      return;
    }

    const isConsoleSink =
      /^(console|logger|log)\.(debug|error|info|log|warn)$/u.test(calleeText);
    const isUtilFormatSink =
      calleeText === 'util.format' || calleeText === 'util.formatWithOptions';

    if (!isConsoleSink && !isUtilFormatSink) {
      return;
    }

    if (
      !isRequestDerivedExpression(
        firstArgument,
        taintedNames,
        context.sourceText,
      )
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.untrustedFormatString,
        node,
        nodeIds: context.nodeIds,
        props: {
          sink: calleeText,
        },
        text: calleeText,
      }),
    );
  });

  return facts;
}

export function collectBrowserOriginFacts(
  context: TypeScriptFactDetectorContext,
  functionBindings: ReadonlyMap<string, FunctionLikeNode>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (
      calleeText &&
      /(?:^|\.)(addEventListener)$/u.test(calleeText) &&
      getLiteralString(node.arguments[0] as TSESTree.Expression) === 'message'
    ) {
      const handler = resolveFunctionLike(
        node.arguments[1] as TSESTree.Expression | undefined,
        functionBindings,
      );

      if (handler && !hasOriginCheck(handler, context.sourceText)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.messageHandlerOriginMissing,
            node,
            nodeIds: context.nodeIds,
            text: calleeText,
          }),
        );
      }
    }

    if (
      calleeText &&
      /(?:^|\.)(postMessage)$/u.test(calleeText) &&
      getLiteralString(node.arguments[1] as TSESTree.Expression) === '*'
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.postMessageWildcardOrigin,
          node,
          nodeIds: context.nodeIds,
          text: calleeText,
        }),
      );
    }
  });

  return facts;
}

export function collectModuleLoadFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
  validatedTrustBoundaries: TrustBoundaryValidationState,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);
      const argument = node.arguments[0];

      if (
        calleeText &&
        trustBoundaryModuleLoaderCallees.has(calleeText) &&
        argument &&
        argument.type !== 'SpreadElement' &&
        isRequestDerivedExpression(argument, taintedNames, context.sourceText) &&
        !isValidatedTrustBoundaryExpression(
          argument,
          validatedTrustBoundaries,
          context.sourceText,
        )
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.importUsingUserInput,
            node,
            nodeIds: context.nodeIds,
            text: 'require',
          }),
        );
      }

      return;
    }

    if (
      node.type !== 'ImportExpression' ||
      !isRequestDerivedExpression(node.source, taintedNames, context.sourceText) ||
      isValidatedTrustBoundaryExpression(
        node.source,
        validatedTrustBoundaries,
        context.sourceText,
      )
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.importUsingUserInput,
        node,
        nodeIds: context.nodeIds,
        text: 'import',
      }),
    );
  });

  return facts;
}

export function collectWebsocketFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'NewExpression') {
      return;
    }

    const calleeText = getNodeText(node.callee, context.sourceText);
    const firstArgument = getStringLiteralArgument(node);

    if (
      calleeText === 'WebSocket' &&
      isInsecureWebsocketUrl(firstArgument)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.insecureWebsocketTransport,
          node,
          nodeIds: context.nodeIds,
          props: {
            url: firstArgument,
          },
          text: excerptFor(node, context.sourceText),
        }),
      );
    }
  });

  return facts;
}
