import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  externalHttpProcessorId,
  matchPrivacyProcessorRecipe,
  type PrivacyProcessorCategory,
  type PrivacyProcessorSinkKind,
} from './privacy-processor-recipes';
import { isPrivacySafeWrapperCall } from './privacy-substrate';
import { collectPrivacyDatatypes } from './privacy-vocabulary';
import {
  createObservedFact,
  getCalleeText,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
  walkAst,
} from './shared';
import {
  getOutboundTargetExpression,
  isExternalNetworkUrlLiteral,
} from './outbound-network';

const sensitiveEgressKind = 'security.sensitive-data-egress' as const;

function isCallExpression(node: TSESTree.Node): node is TSESTree.CallExpression {
  return node.type === 'CallExpression';
}

function getCallCalleeText(
  callExpression: TSESTree.CallExpression,
  sourceText: string,
): string | undefined {
  return getCalleeText(callExpression.callee, sourceText);
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

  return Boolean(matchPrivacyProcessorRecipe(calleeText));
}

function getObjectName(calleeText: string | undefined): string | undefined {
  const match = /^([A-Za-z_$][A-Za-z0-9_$]*)\./u.exec(calleeText ?? '');

  return match?.[1];
}

interface EgressProcessorMatch {
  processorId: string;
  processorCategory: PrivacyProcessorCategory;
  sinkKind: PrivacyProcessorSinkKind;
}

function collectFactForCall(
  context: TypeScriptFactDetectorContext,
  callExpression: TSESTree.CallExpression,
  sdkBindings: ReadonlyMap<string, EgressProcessorMatch>,
): ObservedFact | undefined {
  const calleeText = getCallCalleeText(callExpression, context.sourceText);
  const boundProcessor = sdkBindings.get(getObjectName(calleeText) ?? '');

  if (!calleeText || (!isExternalProcessorCall(calleeText) && !boundProcessor)) {
    return undefined;
  }

  const recipe = matchPrivacyProcessorRecipe(calleeText);
  const httpClientSink =
    calleeText === 'fetch' ||
    calleeText.endsWith('.fetch') ||
    calleeText === 'axios' ||
    calleeText === 'axios.request' ||
    /^axios\.(delete|get|head|options|patch|post|put)$/i.test(calleeText);

  let processor: EgressProcessorMatch | undefined;

  if (boundProcessor) {
    processor = boundProcessor;
  } else if (recipe) {
    processor = {
      processorId: recipe.id,
      processorCategory: recipe.category,
      sinkKind: 'sdk',
    };
  }

  if (httpClientSink) {
    const target = getOutboundTargetExpression(callExpression, calleeText);

    if (!target || !isExternalUrlLiteral(target)) {
      return undefined;
    }

    processor ??= {
      processorId: externalHttpProcessorId,
      processorCategory: 'external-api',
      sinkKind: 'http',
    };
  }

  if (!processor) {
    return undefined;
  }

  const datatypes = callExpression.arguments.flatMap((argument) => {
    if (argument.type === 'SpreadElement') {
      return [];
    }

    return collectPrivacyDatatypes(argument, context.sourceText);
  });

  const normalizedDatatypes = [...new Set(datatypes)].sort();

  if (normalizedDatatypes.length === 0) {
    return undefined;
  }

  return createObservedFact({
    appliesTo: 'block',
    kind: sensitiveEgressKind,
    node: callExpression,
    nodeIds: context.nodeIds,
    props: {
      callee: calleeText,
      rawCallee: calleeText,
      processorCategory: processor.processorCategory,
      processorId: processor.processorId,
      sinkKind: processor.sinkKind,
      datatypes: normalizedDatatypes,
      sensitiveSignals: normalizedDatatypes,
    },
    text: context.sourceText.slice(callExpression.range[0], callExpression.range[1]),
  });
}

function collectSdkBindings(sourceText: string): Map<string, EgressProcessorMatch> {
  const bindings = new Map<string, EgressProcessorMatch>();
  const recipes: Array<{
    pattern: RegExp;
    processor: EgressProcessorMatch;
  }> = [
    {
      pattern:
        /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:new\s+)?(?:Analytics|AnalyticsBrowser\.load|Segment|analytics)\b/gu,
      processor: {
        processorId: 'segment',
        processorCategory: 'analytics',
        sinkKind: 'sdk',
      },
    },
    {
      pattern:
        /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:new\s+)?(?:StatsD|Datadog|DD_RUM|tracer)\b/gu,
      processor: {
        processorId: 'datadog',
        processorCategory: 'observability',
        sinkKind: 'sdk',
      },
    },
    {
      pattern:
        /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:new\s+)?(?:Bugsnag|bugsnag)\b/gu,
      processor: {
        processorId: 'bugsnag',
        processorCategory: 'error-monitoring',
        sinkKind: 'sdk',
      },
    },
    {
      pattern:
        /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:new\s+)?(?:Notifier|Airbrake|airbrake)\b/gu,
      processor: {
        processorId: 'airbrake',
        processorCategory: 'error-monitoring',
        sinkKind: 'sdk',
      },
    },
    {
      pattern:
        /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:algoliasearch|.*\.initIndex)\s*\(/gu,
      processor: {
        processorId: 'algolia',
        processorCategory: 'search',
        sinkKind: 'sdk',
      },
    },
    {
      pattern:
        /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:new\s+)?(?:Client|Elasticsearch|elastic)\b/gu,
      processor: {
        processorId: 'elasticsearch',
        processorCategory: 'search',
        sinkKind: 'sdk',
      },
    },
    {
      pattern:
        /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:trace\.getTracer|tracer\.startSpan|new\s+Span|span)\b/gu,
      processor: {
        processorId: 'open_telemetry',
        processorCategory: 'observability',
        sinkKind: 'sdk',
      },
    },
    {
      pattern:
        /\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:new\s+)?(?:NewRelic|newrelic|newRelic)\b/gu,
      processor: {
        processorId: 'new_relic',
        processorCategory: 'apm',
        sinkKind: 'sdk',
      },
    },
  ];

  for (const recipe of recipes) {
    for (const match of sourceText.matchAll(recipe.pattern)) {
      bindings.set(match[1], recipe.processor);
    }
  }

  return bindings;
}

export const collectSensitiveEgressFacts: TypeScriptFactDetector = (
  context,
) => {
  const facts: ObservedFact[] = [];
  const sdkBindings = collectSdkBindings(context.sourceText);

  walkAst(context.program, (candidate) => {
    if (!isCallExpression(candidate)) {
      return;
    }

    if (isPrivacySafeWrapperCall(candidate, context.sourceText)) {
      return;
    }

    const fact = collectFactForCall(context, candidate, sdkBindings);

    if (fact) {
      facts.push(fact);
    }
  });

  return facts;
};
