import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  excerptFor,
  getCalleeText,
  getObjectProperty,
  getStringLiteralValue,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
  walkAst,
} from './shared';
import { isAllInterfacesHostname } from './outbound-network';

const BIND_FACT_KIND = 'security.bind-to-all-interfaces';

interface BindMatch {
  host: string;
  matchNode: TSESTree.Node;
  sink: string;
  textNode: TSESTree.Node;
}

function getPropertyStringValue(
  property: TSESTree.Property | undefined,
): string | undefined {
  const value = property?.value;

  if (
    !value ||
    value.type === 'AssignmentPattern' ||
    value.type === 'TSEmptyBodyFunctionExpression'
  ) {
    return undefined;
  }

  return getStringLiteralValue(value);
}

function getAllInterfacesPropertyMatch(
  objectExpression: TSESTree.ObjectExpression,
): { host: string; matchNode: TSESTree.Node } | undefined {
  for (const propertyName of ['host', 'hostname']) {
    const property = getObjectProperty(objectExpression, propertyName);
    const host = getPropertyStringValue(property);

    if (host && isAllInterfacesHostname(host)) {
      return {
        host,
        matchNode: property ?? objectExpression,
      };
    }
  }

  return undefined;
}

function getExplicitBindMatch(
  node: TSESTree.CallExpression | TSESTree.NewExpression,
  sourceText: string,
): BindMatch | undefined {
  const calleeText = getCalleeText(node.callee, sourceText);

  if (!calleeText) {
    return undefined;
  }

  if (node.type === 'CallExpression' && /(?:^|\.)(?:listen)$/u.test(calleeText)) {
    const firstArgument = node.arguments[0];

    if (
      firstArgument &&
      firstArgument.type !== 'SpreadElement' &&
      firstArgument.type === 'ObjectExpression'
    ) {
      const propertyMatch = getAllInterfacesPropertyMatch(firstArgument);

      if (propertyMatch) {
        return {
          host: propertyMatch.host,
          matchNode: propertyMatch.matchNode,
          sink: calleeText,
          textNode: node,
        };
      }
    }

    const host = node.arguments[1];

    if (
      host &&
      host.type !== 'SpreadElement' &&
      host.type === 'Literal' &&
      typeof host.value === 'string' &&
      isAllInterfacesHostname(host.value)
    ) {
      return {
        host: host.value,
        matchNode: host,
        sink: calleeText,
        textNode: node,
      };
    }
  }

  if (
    node.type === 'CallExpression' &&
    (calleeText === 'Deno.serve' || calleeText === 'Bun.serve')
  ) {
    const firstArgument = node.arguments[0];

    if (
      firstArgument &&
      firstArgument.type !== 'SpreadElement' &&
      firstArgument.type === 'ObjectExpression'
    ) {
      const propertyMatch = getAllInterfacesPropertyMatch(firstArgument);

      if (propertyMatch) {
        return {
          host: propertyMatch.host,
          matchNode: propertyMatch.matchNode,
          sink: calleeText,
          textNode: node,
        };
      }
    }
  }

  if (
    node.type === 'NewExpression' &&
    /(?:^|\.)(?:WebSocketServer|Server)$/u.test(calleeText)
  ) {
    const firstArgument = node.arguments[0];

    if (
      firstArgument &&
      firstArgument.type !== 'SpreadElement' &&
      firstArgument.type === 'ObjectExpression'
    ) {
      const propertyMatch = getAllInterfacesPropertyMatch(firstArgument);

      if (
        propertyMatch &&
        (calleeText.includes('WebSocket') || calleeText === 'ws.Server')
      ) {
        return {
          host: propertyMatch.host,
          matchNode: propertyMatch.matchNode,
          sink: calleeText,
          textNode: node,
        };
      }
    }
  }

  return undefined;
}

export const collectNetworkExposureFacts: TypeScriptFactDetector = (context) => {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression' && node.type !== 'NewExpression') {
      return;
    }

    const match = getExplicitBindMatch(node, context.sourceText);

    if (!match) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: BIND_FACT_KIND,
        node: match.matchNode,
        nodeIds: context.nodeIds,
        props: {
          host: match.host,
          sink: match.sink,
        },
        text: excerptFor(match.textNode, context.sourceText),
      }),
    );
  });

  return facts;
};
