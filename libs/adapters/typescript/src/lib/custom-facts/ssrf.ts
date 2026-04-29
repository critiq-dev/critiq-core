import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  walkAst,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';
import {
  getOutboundTargetExpression,
  isOutboundTransportSink,
  isPrivateHostLiteral,
  isSafeUrlWrapperCall,
} from './outbound-network';

export const SSRF_RULE_ID = 'ts.security.ssrf';
const SSRF_FACT_KIND = 'security.ssrf';

const requestSourcePattern =
  /(?:\b(?:req|request|ctx|context|event)\b(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*|\b(?:query|params|body|headers|cookies|searchParams|formData|payload)\b(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)/u;

const requestTargetHintPattern =
  /\b(?:callbackUrl|dest(?:ination)?|next|redirect|returnTo|returnUrl|target|endpoint)\b/u;

function isOutboundSink(calleeText: string | undefined): boolean {
  return isOutboundTransportSink(calleeText);
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

  if (isSafeUrlWrapperCall(node, sourceText)) {
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

function collectSsrfFromCall(
  context: TypeScriptFactDetectorContext,
  node: TSESTree.CallExpression | TSESTree.NewExpression,
  taintedNames: ReadonlySet<string>,
): ObservedFact | undefined {
  const calleeText = getCalleeText(node.callee, context.sourceText);

  if (!isOutboundSink(calleeText)) {
    return undefined;
  }

  const targetExpression = getOutboundTargetExpression(node, calleeText);

  if (!targetExpression) {
    return undefined;
  }

  if (isSafeUrlWrapperCall(targetExpression, context.sourceText)) {
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
      const propertyValue = getObjectProperty(targetExpression, propertyName)?.value;

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
