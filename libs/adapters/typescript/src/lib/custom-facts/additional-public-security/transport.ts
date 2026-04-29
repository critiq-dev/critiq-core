import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  excerptFor,
  getCalleeText,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import {
  hasOriginCheck,
  isRequestDerivedExpression,
  resolveFunctionLike,
  type FunctionLikeNode,
} from './analysis';
import { FACT_KINDS } from './constants';
import { getLiteralString } from './utils';

export function collectHeaderMisuseFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);
    const headerName = getLiteralString(
      node.arguments[0] as TSESTree.Expression,
    );
    const headerValue = node.arguments[1] as TSESTree.Expression | undefined;

    if (
      calleeText &&
      /(?:^|\.)(header|set|setHeader)$/u.test(calleeText) &&
      headerName &&
      headerValue &&
      isRequestDerivedExpression(headerValue, taintedNames, context.sourceText)
    ) {
      const normalizedHeader = headerName.toLowerCase();

      if (normalizedHeader === 'access-control-allow-origin') {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.insecureAllowOrigin,
            node,
            nodeIds: context.nodeIds,
            props: {
              header: headerName,
            },
            text: calleeText,
          }),
        );
      }

      if (
        normalizedHeader === 'content-security-policy' ||
        normalizedHeader === 'x-frame-options'
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
            text: calleeText,
          }),
        );
      }
    }

    if (calleeText !== 'res.writeHead') {
      return;
    }

    const headerBag = node.arguments[1];

    if (!headerBag || headerBag.type !== 'ObjectExpression') {
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

      if (
        !isRequestDerivedExpression(
          property.value,
          taintedNames,
          context.sourceText,
        )
      ) {
        continue;
      }

      const normalizedHeader = header.toLowerCase();

      if (normalizedHeader === 'access-control-allow-origin') {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.insecureAllowOrigin,
            node,
            nodeIds: context.nodeIds,
            props: {
              header,
            },
            text: calleeText,
          }),
        );
      }

      if (
        normalizedHeader === 'content-security-policy' ||
        normalizedHeader === 'x-frame-options'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.uiRedress,
            node,
            nodeIds: context.nodeIds,
            props: {
              header,
            },
            text: calleeText,
          }),
        );
      }
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
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);
      const argument = node.arguments[0];

      if (
        calleeText === 'require' &&
        argument &&
        argument.type !== 'SpreadElement' &&
        isRequestDerivedExpression(argument, taintedNames, context.sourceText)
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
      !isRequestDerivedExpression(node.source, taintedNames, context.sourceText)
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
    const firstArgument = getLiteralString(
      node.arguments[0] as TSESTree.Expression | undefined,
    );

    if (
      calleeText === 'WebSocket' &&
      typeof firstArgument === 'string' &&
      /^ws:\/\//iu.test(firstArgument)
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
