import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { collectDisclosureSignals } from './disclosure-signals';
import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  isNode,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';
import {
  getOutboundTargetExpression,
  isExternalNetworkUrlLiteral,
} from './outbound-network';

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
  /^Bugsnag\.(leaveBreadcrumb|notify|start)$/i,
  /^cohere\.(chat|generate)$/i,
  /^dataLayer\.push$/i,
  /^DD_RUM\.(addAction|setUser)$/i,
  /^gtag$/i,
  /^Honeybadger\.(notify|notifyAsync|setContext)$/i,
  /^mixpanel\.(capture|group|identify|people\.(append|set)|track)$/i,
  /^(newrelic|newRelic)\.(noticeError|setCustomAttribute|setPageViewName)$/i,
  /^openai\.(chat\.completions\.create|embeddings\.create|responses\.create)$/i,
  /^openai\.createCompletion$/i,
  /^posthog\.(alias|capture|group|identify)$/i,
  /^ReactGA\.event$/i,
  /^resend\./i,
  /^Rollbar\.(critical|debug|error|info|warning)$/i,
  /^segment\.(group|identify|page|track)$/i,
  /^sendgrid\./i,
  /^Sentry\.(addBreadcrumb|captureEvent|captureException|captureMessage|setContext|setExtra|setTag|setUser)$/i,
  /^slack(Webhook)?\.(postMessage|send|notify)$/i,
  /^sentry\.(captureEvent|captureException|captureMessage|setContext|setExtra|setTag|setUser)$/i,
  /^webhook\.(dispatch|post|send)$/i,
  /^window\.dataLayer\.push$/i,
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

function isExternalUrlLiteral(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): boolean {
  return Boolean(
    node &&
      'type' in node &&
      node.type === 'Literal' &&
      typeof node.value === 'string' &&
      isExternalNetworkUrlLiteral(node.value),
  );
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
  return collectDisclosureSignals(node, sourceText, {
    includeDiagnostics: false,
  });
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
    const target = getOutboundTargetExpression(callExpression, calleeText);

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
