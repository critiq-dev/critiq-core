import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  excerptFor,
  getCalleeText,
  isPropertyNamed,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
  walkAst,
} from './shared';

const TLS_FACT_KIND = 'security.tls-verification-disabled';
const HTTP_FACT_KIND = 'security.insecure-http-transport';

const transportSinkNames = new Set([
  'axios',
  'axios.request',
  'fetch',
  'got',
  'http.request',
  'https.request',
]);

const axiosTransportPattern = /^axios\.(delete|get|head|options|patch|post|put)$/;
const gotTransportPattern = /^got(\.(delete|get|head|options|patch|post|put))?$/;
const loopbackHostPattern = /^(localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|::1)$/i;

function isTransportSink(calleeText: string | undefined): boolean {
  if (!calleeText) {
    return false;
  }

  return (
    transportSinkNames.has(calleeText) ||
    axiosTransportPattern.test(calleeText) ||
    gotTransportPattern.test(calleeText)
  );
}

function isHttpUrl(value: string): boolean {
  return /^http:\/\//i.test(value);
}

function isLocalDevelopmentHttpUrl(value: string): boolean {
  if (!isHttpUrl(value)) {
    return false;
  }

  try {
    const url = new URL(value);

    return loopbackHostPattern.test(url.hostname);
  } catch {
    return false;
  }
}

function firstStringArgument(
  node: TSESTree.CallExpression | TSESTree.NewExpression,
): string | undefined {
  const firstArgument = node.arguments[0] as
    | TSESTree.Expression
    | TSESTree.SpreadElement
    | undefined;

  if (!firstArgument || firstArgument.type !== 'Literal') {
    return undefined;
  }

  return typeof firstArgument.value === 'string'
    ? firstArgument.value
    : undefined;
}

function collectTlsDisableFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'Property') {
      if (
        !isPropertyNamed(node.key, 'rejectUnauthorized') ||
        node.value.type !== 'Literal' ||
        node.value.value !== false
      ) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: TLS_FACT_KIND,
          node,
          nodeIds: context.nodeIds,
          text: excerptFor(node, context.sourceText),
          props: {
            option: 'rejectUnauthorized',
            sink: 'tls-agent',
            value: false,
          },
        }),
      );

      return;
    }

    if (node.type !== 'AssignmentExpression') {
      return;
    }

    const leftText = excerptFor(node.left, context.sourceText);

    if (
      !/^process\.env\.NODE_TLS_REJECT_UNAUTHORIZED$/i.test(leftText) ||
      node.right.type !== 'Literal' ||
      String(node.right.value) !== '0'
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: TLS_FACT_KIND,
        node,
        nodeIds: context.nodeIds,
        text: excerptFor(node, context.sourceText),
        props: {
          option: 'NODE_TLS_REJECT_UNAUTHORIZED',
          sink: 'process.env',
          value: '0',
        },
      }),
    );
  });

  return facts;
}

function collectInsecureHttpFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression' && node.type !== 'NewExpression') {
      return;
    }

    const calleeText = getCalleeText(
      node.callee as Parameters<typeof getCalleeText>[0],
      context.sourceText,
    );

    if (!isTransportSink(calleeText)) {
      return;
    }

    const firstArgument = firstStringArgument(node);

    if (!firstArgument || !isHttpUrl(firstArgument)) {
      return;
    }

    if (isLocalDevelopmentHttpUrl(firstArgument)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: HTTP_FACT_KIND,
        node,
        nodeIds: context.nodeIds,
        text: excerptFor(node, context.sourceText),
        props: {
          sink: calleeText,
          url: firstArgument,
        },
      }),
    );
  });

  return facts;
}

export const collectInsecureTransportFacts: TypeScriptFactDetector = (
  context,
) => {
  const facts = [
    ...collectTlsDisableFacts(context),
    ...collectInsecureHttpFacts(context),
  ];

  return facts;
};
