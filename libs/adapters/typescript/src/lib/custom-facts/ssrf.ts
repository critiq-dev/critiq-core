import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  walkAst,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

export const SSRF_RULE_ID = 'ts.security.ssrf';
const SSRF_FACT_KIND = 'security.ssrf';

const outboundSinkNames = new Set([
  'axios',
  'axios.delete',
  'axios.get',
  'axios.head',
  'axios.options',
  'axios.patch',
  'axios.post',
  'axios.put',
  'axios.request',
  'fetch',
  'got',
  'got.delete',
  'got.get',
  'got.head',
  'got.options',
  'got.patch',
  'got.post',
  'got.put',
  'http.request',
  'https.request',
]);

const safeUrlWrapperNames = new Set([
  'allowlistedUrl',
  'assertAllowedHost',
  'assertAllowedUrl',
  'ensureAllowedUrl',
  'normalizeAllowedUrl',
  'normalizeRedirectTarget',
  'safeUrl',
  'validateAllowedUrl',
  'validateUrl',
]);

const requestSourcePattern =
  /(?:\b(?:req|request|ctx|context|event)\b(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*|\b(?:query|params|body|headers|cookies|searchParams|formData|payload)\b(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)/u;

const requestTargetHintPattern =
  /\b(?:callbackUrl|dest(?:ination)?|next|redirect|returnTo|returnUrl|target|endpoint)\b/u;

const privateHostPattern =
  /(?:^|[^A-Za-z0-9])(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|169\.254\.169\.254|metadata\.google\.internal|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|\[::1\])/iu;

const urlPattern = /^https?:\/\//iu;

function isOutboundSink(calleeText: string | undefined): boolean {
  return Boolean(calleeText && outboundSinkNames.has(calleeText));
}

function isSafeWrapperCall(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): boolean {
  if (!node || node.type !== 'CallExpression') {
    return false;
  }

  const calleeText = getCalleeText(node.callee, sourceText);

  return Boolean(calleeText && safeUrlWrapperNames.has(calleeText));
}

function isPrivateHostLiteral(text: string | undefined): boolean {
  if (!text) {
    return false;
  }

  if (privateHostPattern.test(text)) {
    return true;
  }

  if (!urlPattern.test(text)) {
    return false;
  }

  try {
    const url = new URL(text);
    const hostname = url.hostname.toLowerCase();

    return (
      hostname === 'localhost' ||
      hostname === 'metadata.google.internal' ||
      hostname === '0.0.0.0' ||
      hostname === '::1' ||
      hostname.startsWith('127.') ||
      hostname.startsWith('10.') ||
      hostname.startsWith('192.168.') ||
      /^172\.(?:1[6-9]|2\d|3[0-1])\./u.test(hostname) ||
      hostname === '169.254.169.254'
    );
  } catch {
    return false;
  }
}

function getExpressionText(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string | undefined {
  if (!node) {
    return undefined;
  }

  return getNodeText(node, sourceText);
}

function isRequestDerivedExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  taintedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  if (!node) {
    return false;
  }

  if (node.type === 'Identifier') {
    return taintedNames.has(node.name);
  }

  if (isSafeWrapperCall(node, sourceText)) {
    return false;
  }

  const text = getExpressionText(node, sourceText);

  if (!text) {
    return false;
  }

  if (requestSourcePattern.test(text)) {
    return true;
  }

  if (requestTargetHintPattern.test(text) && text.length < 400) {
    return true;
  }

  switch (node.type) {
    case 'BinaryExpression':
    case 'LogicalExpression':
      return (
        isRequestDerivedExpression(node.left, taintedNames, sourceText) ||
        isRequestDerivedExpression(node.right, taintedNames, sourceText)
      );
    case 'ConditionalExpression':
      return (
        isRequestDerivedExpression(node.test, taintedNames, sourceText) ||
        isRequestDerivedExpression(node.consequent, taintedNames, sourceText) ||
        isRequestDerivedExpression(node.alternate, taintedNames, sourceText)
      );
    case 'TemplateLiteral':
      return node.expressions.some((expression) =>
        isRequestDerivedExpression(expression, taintedNames, sourceText),
      );
    case 'ArrayExpression':
      return node.elements.some((element) =>
        element ? isRequestDerivedExpression(element, taintedNames, sourceText) : false,
      );
    case 'ObjectExpression':
      return node.properties.some((property) => {
        if (property.type === 'Property') {
          return (
            isRequestDerivedExpression(property.key, taintedNames, sourceText) ||
            isRequestDerivedExpression(property.value, taintedNames, sourceText)
          );
        }

        return isRequestDerivedExpression(property.argument, taintedNames, sourceText);
      });
    case 'MemberExpression':
      return requestSourcePattern.test(text);
    case 'CallExpression':
    case 'NewExpression':
      return node.arguments.some((argument) =>
        isRequestDerivedExpression(argument, taintedNames, sourceText),
      );
    case 'AwaitExpression':
      return isRequestDerivedExpression(node.argument, taintedNames, sourceText);
    case 'ChainExpression':
      return isRequestDerivedExpression(node.expression, taintedNames, sourceText);
    case 'UnaryExpression':
      return isRequestDerivedExpression(node.argument, taintedNames, sourceText);
    case 'TSAsExpression':
    case 'TSTypeAssertion':
      return isRequestDerivedExpression(node.expression, taintedNames, sourceText);
    default:
      return false;
  }
}

function collectTaintedNames(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const taintedNames = new Set<string>();

  walkAst(context.program, (node) => {
    if (node.type === 'VariableDeclarator') {
      if (node.id.type !== 'Identifier' || !node.init) {
        return;
      }

      if (isRequestDerivedExpression(node.init, taintedNames, context.sourceText)) {
        taintedNames.add(node.id.name);
      }

      return;
    }

    if (node.type !== 'AssignmentExpression') {
      return;
    }

    if (node.left.type !== 'Identifier') {
      return;
    }

    if (isRequestDerivedExpression(node.right, taintedNames, context.sourceText)) {
      taintedNames.add(node.left.name);
    }
  });

  return taintedNames;
}

function getCallTargetExpression(
  node: TSESTree.CallExpression | TSESTree.NewExpression,
): TSESTree.Expression | TSESTree.SpreadElement | undefined {
  return node.arguments.find(
    (argument): argument is TSESTree.Expression => argument.type !== 'SpreadElement',
  );
}

function getOptionPropertyValue(
  node: TSESTree.ObjectExpression,
  name: string,
): TSESTree.Node | TSESTree.PrivateIdentifier | undefined {
  const property = node.properties.find(
    (entry): entry is TSESTree.Property =>
      entry.type === 'Property' &&
      ((entry.key.type === 'Identifier' && entry.key.name === name) ||
        (entry.key.type === 'Literal' && entry.key.value === name)),
  );

  if (!property) {
    return undefined;
  }

  return property.value;
}

function collectSsrfFromCall(
  context: TypeScriptFactDetectorContext,
  node: TSESTree.CallExpression | TSESTree.NewExpression,
  taintedNames: ReadonlySet<string>,
): ObservedFact | undefined {
  const calleeText = getCalleeText(node.callee, context.sourceText);

  if (!isOutboundSink(calleeText)) {
    return undefined;
  }

  const targetExpression = getCallTargetExpression(node);

  if (!targetExpression) {
    return undefined;
  }

  if (isSafeWrapperCall(targetExpression, context.sourceText)) {
    return undefined;
  }

  const targetText = getExpressionText(targetExpression, context.sourceText);
  let reason: 'private-host' | 'request-controlled-target' | undefined;

  if (isPrivateHostLiteral(targetText)) {
    reason = 'private-host';
  } else if (
    isRequestDerivedExpression(targetExpression, taintedNames, context.sourceText)
  ) {
    reason = 'request-controlled-target';
  } else if (targetText && requestSourcePattern.test(targetText)) {
    reason = 'request-controlled-target';
  }

  if (!reason && targetExpression.type === 'ObjectExpression') {
    for (const propertyName of ['host', 'hostname', 'url', 'uri']) {
      const propertyValue = getOptionPropertyValue(targetExpression, propertyName);

      if (!propertyValue) {
        continue;
      }

      const propertyText = getExpressionText(propertyValue, context.sourceText);

      if (isPrivateHostLiteral(propertyText)) {
        reason = 'private-host';
        break;
      }

      if (
        isRequestDerivedExpression(propertyValue, taintedNames, context.sourceText)
      ) {
        reason = 'request-controlled-target';
        break;
      }
    }
  }

  if (!reason) {
    return undefined;
  }

  return createObservedFact({
    appliesTo: 'block',
    kind: SSRF_FACT_KIND,
    node,
    nodeIds: context.nodeIds,
    props: {
      reason,
      sink: calleeText,
      target: targetText,
    },
    text: getNodeText(node, context.sourceText),
  });
}

export const collectSsrfFacts: TypeScriptFactDetector = (context) => {
  const taintedNames = collectTaintedNames(context);
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression' && node.type !== 'NewExpression') {
      return;
    }

    const fact = collectSsrfFromCall(context, node, taintedNames);

    if (fact) {
      facts.push(fact);
    }
  });

  return facts;
};
