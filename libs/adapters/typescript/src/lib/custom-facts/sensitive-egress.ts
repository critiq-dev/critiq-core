import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  getStringLiteralValue,
  isNode,
  looksSensitiveIdentifier,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

const sensitiveEgressKind = 'security.sensitive-data-egress' as const;

const safeWrapperNames = new Set([
  'dropSensitiveFields',
  'maskSensitiveData',
  'redact',
  'redactSensitiveData',
  'sanitizePayload',
  'stripSensitiveFields',
]);

const externalProcessorCallPatterns = [
  /^analytics\.(capture|group|identify|page|track)$/i,
  /^amplitude\.(identify|logEvent|track)$/i,
  /^cohere\.(chat|generate)$/i,
  /^mixpanel\.(capture|group|identify|people\.(append|set)|track)$/i,
  /^openai\.(chat\.completions\.create|embeddings\.create|responses\.create)$/i,
  /^posthog\.(alias|capture|group|identify)$/i,
  /^resend\./i,
  /^segment\.(group|identify|page|track)$/i,
  /^sendgrid\./i,
  /^slack(Webhook)?\.(postMessage|send|notify)$/i,
  /^sentry\.(captureEvent|captureException|captureMessage|setContext|setUser)$/i,
  /^webhook\.(dispatch|post|send)$/i,
];

function isCallExpression(node: TSESTree.Node): node is TSESTree.CallExpression {
  return node.type === 'CallExpression';
}

function getCallCalleeText(
  callExpression: TSESTree.CallExpression,
  sourceText: string,
): string | undefined {
  return getCalleeText(callExpression.callee, sourceText);
}

function isSafeWrapperCall(
  node: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  const calleeText = getCallCalleeText(node, sourceText);

  if (!calleeText) {
    return false;
  }

  return Boolean(calleeText && safeWrapperNames.has(calleeText));
}

function isIdentifierSensitive(text: string | undefined): boolean {
  if (!text) {
    return false;
  }

  return looksSensitiveIdentifier(text) || /\b(email|phone|address|dob|ssn|token|jwt|secret|password|card|billing|support|profile)\b/i.test(text);
}

function isLocalOrInternalHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '::1' ||
    hostname === '[::1]' ||
    hostname.startsWith('127.') ||
    hostname.startsWith('10.') ||
    hostname.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(hostname) ||
    hostname === '169.254.169.254'
  );
}

function isExternalUrlLiteral(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): boolean {
  const literal = getStringLiteralValue(node);

  if (!literal) {
    return false;
  }

  if (!/^https?:\/\//i.test(literal)) {
    return false;
  }

  try {
    const parsed = new URL(literal);

    return !isLocalOrInternalHost(parsed.hostname);
  } catch {
    return !/localhost|127\.0\.0\.1|169\.254\.169\.254/i.test(literal);
  }
}

function isExternalProcessorCall(calleeText: string | undefined): boolean {
  if (!calleeText) {
    return false;
  }

  if (calleeText === 'fetch' || calleeText.endsWith('.fetch')) {
    return true;
  }

  if (calleeText === 'axios' || calleeText === 'axios.request') {
    return true;
  }

  if (/^axios\.(delete|get|head|options|patch|post|put)$/i.test(calleeText)) {
    return true;
  }

  return externalProcessorCallPatterns.some((pattern) => pattern.test(calleeText));
}

function isKnownOutboundProcessor(calleeText: string | undefined): boolean {
  return Boolean(calleeText) && isExternalProcessorCall(calleeText);
}

function visitNodes(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
  visitor: (candidate: TSESTree.Node) => void,
): void {
  if (!node || node.type === 'PrivateIdentifier') {
    return;
  }

  visitor(node);

  if (node.type === 'CallExpression' && isSafeWrapperCall(node, sourceText)) {
    return;
  }

  for (const value of Object.values(node)) {
    if (!value) {
      continue;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        if (entry && typeof entry === 'object' && 'type' in entry) {
          visitNodes(entry as TSESTree.Node, sourceText, visitor);
        }
      }

      continue;
    }

    if (value && typeof value === 'object' && 'type' in value) {
      visitNodes(value as TSESTree.Node, sourceText, visitor);
    }
  }
}

function collectSensitiveSignalsFromNode(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string[] {
  if (!node) {
    return [];
  }

  const signals = new Set<string>();

  visitNodes(node, sourceText, (candidate) => {
    if (candidate.type === 'CallExpression' && isSafeWrapperCall(candidate, sourceText)) {
      return;
    }

    if (candidate.type === 'Identifier' && isIdentifierSensitive(candidate.name)) {
      signals.add(candidate.name);
      return;
    }

    if (candidate.type === 'MemberExpression') {
      const memberText = getNodeText(candidate, sourceText);

      if (memberText && isIdentifierSensitive(memberText)) {
        signals.add(memberText);
      }
      return;
    }

    if (candidate.type === 'Property') {
      const keyText = getNodeText(candidate.key, sourceText);

      if (isIdentifierSensitive(keyText)) {
        signals.add(keyText ?? 'sensitive');
      }
    }
  });

  return [...signals].sort((left, right) => left.localeCompare(right));
}

function getFetchOrAxiosTarget(
  callExpression: TSESTree.CallExpression,
  calleeText: string | undefined,
): TSESTree.Expression | undefined {
  if (!calleeText) {
    return undefined;
  }

  if (calleeText === 'fetch' || calleeText.endsWith('.fetch')) {
    return callExpression.arguments[0] && callExpression.arguments[0].type !== 'SpreadElement'
      ? callExpression.arguments[0]
      : undefined;
  }

  if (calleeText === 'axios' || calleeText === 'axios.request') {
    const firstArgument = callExpression.arguments[0];

    if (!firstArgument || firstArgument.type === 'SpreadElement') {
      return undefined;
    }

    if (firstArgument.type === 'ObjectExpression') {
      const urlProperty = getObjectProperty(firstArgument, 'url');
      const value = urlProperty?.value;

      return value && 'type' in value ? (value as TSESTree.Expression) : undefined;
    }

    return firstArgument;
  }

  if (/^axios\.(delete|get|head|options|patch|post|put)$/i.test(calleeText)) {
    const targetArgument = callExpression.arguments[0];

    return targetArgument && targetArgument.type !== 'SpreadElement'
      ? targetArgument
      : undefined;
  }

  return undefined;
}

function collectFactForCall(
  context: TypeScriptFactDetectorContext,
  callExpression: TSESTree.CallExpression,
): ObservedFact | undefined {
  const calleeText = getCallCalleeText(callExpression, context.sourceText);

  if (!calleeText || !isKnownOutboundProcessor(calleeText)) {
    return undefined;
  }

  const processorSink = externalProcessorCallPatterns.some((pattern) =>
    pattern.test(calleeText),
  );
  const httpClientSink =
    calleeText === 'fetch' ||
    calleeText.endsWith('.fetch') ||
    calleeText === 'axios' ||
    calleeText === 'axios.request' ||
    /^axios\.(delete|get|head|options|patch|post|put)$/i.test(calleeText);

  if (httpClientSink) {
    const target = getFetchOrAxiosTarget(callExpression, calleeText);

    if (!target || !isExternalUrlLiteral(target)) {
      return undefined;
    }
  }

  if (!processorSink && !httpClientSink) {
    return undefined;
  }

  const sensitiveSignals = callExpression.arguments.flatMap((argument) => {
    if (argument.type === 'SpreadElement') {
      return [];
    }

    return collectSensitiveSignalsFromNode(argument, context.sourceText);
  });

  if (sensitiveSignals.length === 0) {
    return undefined;
  }

  return createObservedFact({
    appliesTo: 'block',
    kind: sensitiveEgressKind,
    node: callExpression,
    nodeIds: context.nodeIds,
    props: {
      callee: calleeText,
      sensitiveSignals: [...new Set(sensitiveSignals)].sort(),
    },
    text: context.sourceText.slice(callExpression.range[0], callExpression.range[1]),
  });
}

export const collectSensitiveEgressFacts: TypeScriptFactDetector = (
  context,
) => {
  const facts: ObservedFact[] = [];

  visitNodes(context.program, context.sourceText, (candidate) => {
    if (!isCallExpression(candidate)) {
      return;
    }

    const fact = collectFactForCall(context, candidate);

    if (fact) {
      facts.push(fact);
    }
  });

  return facts;
};
