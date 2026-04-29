import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  excerptFor,
  getObjectProperty,
  getCalleeText,
  getStringLiteralValue,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
  walkAst,
} from './shared';
import {
  getStringLiteralArgument,
  isOutboundTransportSink,
  isRemotePlainHttpUrl,
} from './outbound-network';

const TLS_FACT_KIND = 'security.tls-verification-disabled';
const HTTP_FACT_KIND = 'security.insecure-http-transport';
const WEAK_TLS_FACT_KIND = 'security.weak-tls-version';

function isFunctionLike(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): node is TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression {
  if (!node || node.type === 'PrivateIdentifier') {
    return false;
  }

  return (
    node.type === 'ArrowFunctionExpression' ||
    node.type === 'FunctionExpression'
  );
}

function getExpressionPropertyValue(
  property: TSESTree.Property | undefined,
): TSESTree.Expression | undefined {
  const value = property?.value;

  if (
    !value ||
    value.type === 'AssignmentPattern' ||
    value.type === 'TSEmptyBodyFunctionExpression'
  ) {
    return undefined;
  }

  return value;
}

function isUndefinedLikeExpression(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): boolean {
  if (!node || node.type === 'PrivateIdentifier') {
    return false;
  }

  if (node.type === 'Identifier' && node.name === 'undefined') {
    return true;
  }

  if (node.type === 'Literal') {
    return node.value === null;
  }

  return (
    node.type === 'UnaryExpression' &&
    node.operator === 'void' &&
    node.argument.type === 'Literal' &&
    node.argument.value === 0
  );
}

function isPermissiveCheckServerIdentity(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): boolean {
  if (!isFunctionLike(node)) {
    return false;
  }

  if (node.body.type !== 'BlockStatement') {
    return isUndefinedLikeExpression(node.body);
  }

  if (node.body.body.length === 0) {
    return true;
  }

  const returnStatements = node.body.body.filter(
    (statement): statement is TSESTree.ReturnStatement =>
      statement.type === 'ReturnStatement',
  );

  return (
    returnStatements.length > 0 &&
    returnStatements.every((statement) =>
      isUndefinedLikeExpression(statement.argument),
    )
  );
}

function normalizeTlsPolicyValue(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/gu, '');
}

function isWeakMinVersion(value: string): boolean {
  return /^(?:sslv3|tlsv1(?:\.0)?|tlsv1\.1)$/iu.test(
    normalizeTlsPolicyValue(value),
  );
}

function isWeakSecureProtocol(value: string): boolean {
  return /^(?:sslv3_method|tlsv1_method|tlsv1_1_method)$/iu.test(
    normalizeTlsPolicyValue(value),
  );
}

function collectTlsDisableFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'ObjectExpression') {
      const rejectUnauthorized = getObjectProperty(node, 'rejectUnauthorized');
      const checkServerIdentity = getObjectProperty(node, 'checkServerIdentity');
      const minVersionProperty = getObjectProperty(node, 'minVersion');
      const secureProtocolProperty = getObjectProperty(node, 'secureProtocol');

      if (
        rejectUnauthorized?.value.type === 'Literal' &&
        rejectUnauthorized.value.value === false
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: TLS_FACT_KIND,
            node: rejectUnauthorized,
            nodeIds: context.nodeIds,
            text: excerptFor(rejectUnauthorized, context.sourceText),
            props: {
              option: 'rejectUnauthorized',
              sink: 'tls-agent',
              value: false,
            },
          }),
        );
      }

      if (
        isPermissiveCheckServerIdentity(
          getExpressionPropertyValue(checkServerIdentity),
        )
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: TLS_FACT_KIND,
            node: checkServerIdentity ?? node,
            nodeIds: context.nodeIds,
            text: excerptFor(checkServerIdentity ?? node, context.sourceText),
            props: {
              option: 'checkServerIdentity',
              sink: 'tls-agent',
              value: 'permissive-callback',
            },
          }),
        );
      }

      const minVersion = getStringLiteralValue(
        getExpressionPropertyValue(minVersionProperty),
      );

      if (minVersion && isWeakMinVersion(minVersion)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: WEAK_TLS_FACT_KIND,
            node: minVersionProperty ?? node,
            nodeIds: context.nodeIds,
            text: excerptFor(minVersionProperty ?? node, context.sourceText),
            props: {
              option: 'minVersion',
              value: minVersion,
            },
          }),
        );
      }

      const secureProtocol = getStringLiteralValue(
        getExpressionPropertyValue(secureProtocolProperty),
      );

      if (secureProtocol && isWeakSecureProtocol(secureProtocol)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: WEAK_TLS_FACT_KIND,
            node: secureProtocolProperty ?? node,
            nodeIds: context.nodeIds,
            text: excerptFor(secureProtocolProperty ?? node, context.sourceText),
            props: {
              option: 'secureProtocol',
              value: secureProtocol,
            },
          }),
        );
      }
    }

    if (node.type !== 'AssignmentExpression') {
      return;
    }

    const leftText = excerptFor(node.left, context.sourceText);

    if (
      /^process\.env\.NODE_TLS_REJECT_UNAUTHORIZED$/i.test(leftText) &&
      node.right.type === 'Literal' &&
      String(node.right.value) === '0'
    ) {
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
    }
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

    if (!isOutboundTransportSink(calleeText)) {
      return;
    }

    const firstArgument = getStringLiteralArgument(node);

    if (!isRemotePlainHttpUrl(firstArgument)) {
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
